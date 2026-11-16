package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/names"
	"github.com/henry40408/toolward/internal/rawjson"
	"github.com/henry40408/toolward/internal/upstream"
)

const cancelReason = "cancelled by the client"

func unavailable(server string, reason error) *mcpwire.Error {
	return mcpwire.InternalError(fmt.Sprintf("upstream %q is unavailable: %v", server, reason))
}

// splitName splits "<server>__<name>" at the first separator.
func splitName(exposed string) (server, name string, ok bool) {
	return strings.Cut(exposed, names.Separator)
}

// upstreamError turns a failed upstream request into the error for the agent.
// The upstream's own MCP error keeps its code. Every text is masked, because
// it may contain what the server echoed back.
func upstreamError(u *upstream.Upstream, err error) error {
	var rpcErr *mcpwire.Error
	if !errors.As(err, &rpcErr) {
		return mcpwire.InternalError(u.Redact(fmt.Sprintf("upstream request failed: %v", err)))
	}
	encoded, marshalErr := json.Marshal(rpcErr)
	if marshalErr != nil {
		return mcpwire.InternalError(marshalErr.Error())
	}
	masked, redactErr := u.RedactResult(encoded)
	if redactErr != nil {
		return mcpwire.InternalError(redactErr.Error())
	}
	var result mcpwire.Error
	if json.Unmarshal(masked, &result) != nil {
		return mcpwire.InternalError("upstream request failed")
	}
	return &result
}

// forward sends params upstream and returns the masked result.
func forward(ctx context.Context, u *upstream.Upstream, session *mcpwire.Session, method string, params json.RawMessage) (json.RawMessage, error) {
	result, err := session.Call(ctx, method, params)
	if err != nil {
		return nil, upstreamError(u, err)
	}
	masked, err := u.RedactResult(result)
	if err != nil {
		return nil, mcpwire.InternalError(err.Error())
	}
	return masked, nil
}

// withResultType returns result with "resultType":"complete" when it has
// none. Upstreams on older protocol revisions omit it, which the 2026-07-28
// revision spoken to the agent requires.
func withResultType(result json.RawMessage) (json.RawMessage, error) {
	if rawjson.Raw(result, "resultType") != nil {
		return result, nil
	}
	return rawjson.SetString(result, "resultType", "complete")
}

type callParams struct {
	Name string `json:"name"`
}

func (p *Proxy) callTool(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	var request callParams
	if err := json.Unmarshal(params, &request); err != nil {
		return nil, mcpwire.InvalidParams(fmt.Sprintf("invalid params: %v", err))
	}
	unknown := mcpwire.InvalidParams(fmt.Sprintf("unknown tool %q", request.Name))
	server, called, ok := splitName(request.Name)
	if !ok || p.upstreams[server] == nil {
		return nil, unknown
	}
	u := p.upstreams[server]
	original, found, err := u.OriginalTool(ctx, called)
	if err != nil {
		return nil, unavailable(server, err)
	}
	if !found {
		return nil, unknown
	}
	session, err := u.Peer(ctx)
	if err != nil {
		return nil, unavailable(server, err)
	}
	renamed, err := rawjson.SetString(params, "name", original)
	if err != nil {
		return nil, mcpwire.InternalError(err.Error())
	}
	result, err := callCancellable(ctx, u, session, renamed)
	if err != nil {
		return nil, err
	}
	return toolResult(result)
}

// callCancellable forwards a tool call. When the agent cancels its request,
// the upstream gets `notifications/cancelled` too, so a long-running tool
// stops as well.
func callCancellable(ctx context.Context, u *upstream.Upstream, session *mcpwire.Session, params json.RawMessage) (json.RawMessage, error) {
	callCtx, cancel := context.WithCancelCause(context.WithoutCancel(ctx))
	defer cancel(nil)
	stop := context.AfterFunc(ctx, func() { cancel(errors.New(cancelReason)) })
	defer stop()
	return forward(callCtx, u, session, "tools/call", params)
}

// toolResult accepts the result shapes of tools/call and completes the
// ordinary one. A shape added later cannot be inspected, so it is not passed
// on.
func toolResult(result json.RawMessage) (json.RawMessage, error) {
	resultType, _ := rawjson.String(result, "resultType")
	switch resultType {
	case "input_required", "task":
		return result, nil
	case "", "complete":
		if !hasToolOutcome(result) {
			return nil, mcpwire.InternalError("unsupported upstream result")
		}
		completed, err := withResultType(result)
		if err != nil {
			return nil, mcpwire.InternalError(err.Error())
		}
		return completed, nil
	}
	return nil, mcpwire.InternalError("unsupported upstream result")
}

func hasToolOutcome(result json.RawMessage) bool {
	for _, key := range []string{"content", "structuredContent", "isError"} {
		if rawjson.Raw(result, key) != nil {
			return true
		}
	}
	return false
}
