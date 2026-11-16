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

// forwardRequest is one request to an upstream, over a session already
// obtained from it.
type forwardRequest struct {
	Upstream *upstream.Upstream
	Session  *mcpwire.Session
	Method   string
	Params   json.RawMessage
}

// forward sends the request upstream and returns the masked result.
func forward(ctx context.Context, req forwardRequest) (json.RawMessage, error) {
	result, err := req.Session.Call(ctx, req.Method, req.Params)
	if err != nil {
		return nil, upstreamError(req.Upstream, err)
	}
	masked, err := req.Upstream.RedactResult(result)
	if err != nil {
		return nil, mcpwire.InternalError(err.Error())
	}
	return masked, nil
}

// present is false for an absent key and for JSON null, which the Rust
// version (typed Option fields) also treated as absent.
func present(value json.RawMessage) bool {
	return value != nil && string(value) != "null"
}

// withResultType returns result with "resultType":"complete" when it has
// none. Upstreams on older protocol revisions omit it, which the 2026-07-28
// revision spoken to the agent requires.
func withResultType(result json.RawMessage) (json.RawMessage, error) {
	if present(rawjson.Raw(result, "resultType")) {
		return result, nil
	}
	return rawjson.SetString(result, "resultType", "complete")
}

// withContent returns result with "content":[] when it has none: the schema
// requires the field, and the Rust version's typed result always wrote it.
func withContent(result json.RawMessage) (json.RawMessage, error) {
	if present(rawjson.Raw(result, "content")) {
		return result, nil
	}
	return rawjson.SetRaw(result, "content", json.RawMessage("[]"))
}

type callParams struct {
	Name string `json:"name"`
}

func (p *Proxy) callTool(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	var request callParams
	if err := json.Unmarshal(params, &request); err != nil {
		return nil, mcpwire.InvalidParams(fmt.Sprintf("invalid params: %v", err))
	}
	u, original, err := p.resolveTool(ctx, request.Name)
	if err != nil {
		return nil, err
	}
	session, err := u.Peer(ctx)
	if err != nil {
		return nil, unavailable(u.Name(), err)
	}
	renamed, err := rawjson.SetString(params, "name", original)
	if err != nil {
		return nil, mcpwire.InternalError(err.Error())
	}
	result, err := callCancellable(ctx, forwardRequest{Upstream: u, Session: session, Method: "tools/call", Params: renamed})
	if err != nil {
		return nil, err
	}
	return toolResult(result)
}

// resolveTool finds the upstream of an exposed tool name and the name that
// upstream knows the tool by.
func (p *Proxy) resolveTool(ctx context.Context, exposed string) (*upstream.Upstream, string, error) {
	unknown := mcpwire.InvalidParams(fmt.Sprintf("unknown tool %q", exposed))
	server, called, ok := splitName(exposed)
	if !ok || p.upstreams[server] == nil {
		return nil, "", unknown
	}
	u := p.upstreams[server]
	original, found, err := u.OriginalTool(ctx, called)
	if err != nil {
		return nil, "", unavailable(server, err)
	}
	if !found {
		return nil, "", unknown
	}
	return u, original, nil
}

// callCancellable forwards a tool call. When the agent cancels its request,
// the upstream gets `notifications/cancelled` too, so a long-running tool
// stops as well.
func callCancellable(ctx context.Context, req forwardRequest) (json.RawMessage, error) {
	callCtx, cancel := context.WithCancelCause(context.WithoutCancel(ctx))
	defer cancel(nil)
	stop := context.AfterFunc(ctx, func() { cancel(errors.New(cancelReason)) })
	defer stop()
	return forward(callCtx, req)
}

// toolResult accepts the result shapes of tools/call and completes the
// ordinary one. A shape added later cannot be inspected, so it is not passed
// on.
func toolResult(result json.RawMessage) (json.RawMessage, error) {
	resultType, _ := rawjson.String(result, "resultType")
	switch resultType {
	// A task handle is passed on as it is. toolward does not serve
	// tasks/get either way, and an upstream only returns one to a client that
	// declared the tasks capability, which toolward does not.
	case "input_required", "task":
		return result, nil
	case "", "complete":
		if !hasToolOutcome(result) {
			return nil, mcpwire.InternalError("unsupported upstream result")
		}
		return completeToolResult(result)
	}
	return nil, mcpwire.InternalError("unsupported upstream result")
}

func completeToolResult(result json.RawMessage) (json.RawMessage, error) {
	completed, err := withContent(result)
	if err == nil {
		completed, err = withResultType(completed)
	}
	if err != nil {
		return nil, mcpwire.InternalError(err.Error())
	}
	return completed, nil
}

func hasToolOutcome(result json.RawMessage) bool {
	for _, key := range []string{"content", "structuredContent", "isError"} {
		if rawjson.Raw(result, key) != nil {
			return true
		}
	}
	return false
}
