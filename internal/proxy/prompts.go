package proxy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/rawjson"
)

func (p *Proxy) getPrompt(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	var request callParams
	if err := json.Unmarshal(params, &request); err != nil {
		return nil, mcpwire.InvalidParams(fmt.Sprintf("invalid params: %v", err))
	}
	unknown := mcpwire.InvalidParams(fmt.Sprintf("unknown prompt %q", request.Name))
	server, prompt, ok := splitName(request.Name)
	if !ok || p.upstreams[server] == nil {
		return nil, unknown
	}
	u := p.upstreams[server]
	session, err := u.Peer(ctx)
	if err != nil {
		return nil, unavailable(server, err)
	}
	renamed, err := rawjson.SetString(params, "name", prompt)
	if err != nil {
		return nil, mcpwire.InternalError(err.Error())
	}
	result, err := forward(ctx, forwardRequest{Upstream: u, Session: session, Method: "prompts/get", Params: renamed})
	if err != nil {
		return nil, err
	}
	completed, err := withResultType(result)
	if err != nil {
		return nil, mcpwire.InternalError(err.Error())
	}
	return completed, nil
}
