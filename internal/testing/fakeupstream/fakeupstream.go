// Package fakeupstream is a tiny stdio MCP server for tests. A test binary
// runs it by calling Run from TestMain when EnvSwitch is set, and tests start
// that binary as the upstream command.
//
// Tools: echo returns its text, env returns the value of the environment
// variable name, fail returns a tool-level error, die exits the process, and
// hang waits for cancellation and then writes the file named by marker.
//
// FAKE_TTL_MS and FAKE_CACHE_SCOPE (public or private) set the caching hints
// of the tool list. Without them the list carries none. FAKE_NO_TOOLS makes
// the server announce prompts only and refuse tools/list. FAKE_LIST_DELAY_MS
// makes the listings slow.
//
// It is built on mcpwire and not on an SDK, because SDKs write a cache scope
// of their own when none is set, and the proxy must be tested against a list
// that has none.
package fakeupstream

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/henry40408/toolward/internal/mcpwire"
)

// EnvSwitch tells a test binary to act as the fake upstream.
const EnvSwitch = "TOOLWARD_FAKE_UPSTREAM"

// HangingNotice is the stderr line the fake writes once a hang call is
// waiting. Tests use it to know that a cancellation reaches a running call.
const HangingNotice = "fake-upstream: hang is waiting"

// Run serves one connection on stdin and stdout until the client leaves.
func Run() {
	handler := newHandler(os.Getenv)
	server := mcpwire.NewServer(mcpwire.ServerConfig{
		Info:         mcpwire.Implementation{Name: "fake-upstream", Version: "0"},
		Capabilities: handler.capabilities(),
		Methods:      handler,
	})
	peer := mcpwire.NewPeer(mcpwire.NewStdioTransport(os.Stdin, os.Stdout), server)
	<-peer.Done()
}

type handler struct {
	noTools   bool
	listDelay time.Duration
	ttlMs     *int
	scope     string
}

func newHandler(getenv func(string) string) *handler {
	h := &handler{noTools: getenv("FAKE_NO_TOOLS") != ""}
	if ms, err := strconv.Atoi(getenv("FAKE_LIST_DELAY_MS")); err == nil {
		h.listDelay = time.Duration(ms) * time.Millisecond
	}
	if ms, err := strconv.Atoi(getenv("FAKE_TTL_MS")); err == nil {
		h.ttlMs = &ms
	}
	if scope := getenv("FAKE_CACHE_SCOPE"); scope == "public" || scope == "private" {
		h.scope = scope
	}
	return h
}

func (h *handler) capabilities() json.RawMessage {
	if h.noTools {
		return json.RawMessage(`{"prompts":{}}`)
	}
	return json.RawMessage(`{"tools":{}}`)
}

func (h *handler) HandleRequest(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	switch method {
	case "tools/list":
		return h.listTools(ctx)
	case "tools/call":
		return h.callTool(ctx, params)
	}
	return nil, mcpwire.MethodNotFound(method)
}

func schema(property string) map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{property: map[string]any{"type": "string"}},
	}
}

func (h *handler) listTools(ctx context.Context) (json.RawMessage, error) {
	if h.noTools {
		return nil, mcpwire.MethodNotFound("tools/list")
	}
	select {
	case <-time.After(h.listDelay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	type tool = map[string]any
	result := map[string]any{"tools": []tool{
		{"name": "echo", "description": "Echo the text", "inputSchema": schema("text")},
		{"name": "env", "description": "Read an environment variable", "inputSchema": schema("name")},
		{"name": "fail", "description": "Always fails", "inputSchema": schema("unused")},
		{"name": "die", "description": "Exits the process", "inputSchema": schema("unused")},
		{"name": "hang", "description": "Waits to be cancelled", "inputSchema": schema("marker")},
	}}
	if h.ttlMs != nil {
		result["ttlMs"] = *h.ttlMs
	}
	if h.scope != "" {
		result["cacheScope"] = h.scope
	}
	return json.Marshal(result)
}

func (h *handler) callTool(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	var call struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return nil, mcpwire.InvalidParams(err.Error())
	}
	switch call.Name {
	case "echo":
		return textResult("echo: "+call.Arguments["text"], false)
	case "env":
		return textResult(envValue(call.Arguments["name"]), false)
	case "fail":
		return textResult("boom", true)
	case "die":
		os.Exit(0)
	case "hang":
		return hang(ctx, call.Arguments["marker"])
	}
	return nil, mcpwire.InvalidParams(fmt.Sprintf("no tool %q", call.Name))
}

func envValue(name string) string {
	value, ok := os.LookupEnv(name)
	if !ok {
		return "<unset>"
	}
	return value
}

// hang leaves a marker file once the request is cancelled.
func hang(ctx context.Context, marker string) (json.RawMessage, error) {
	fmt.Fprintln(os.Stderr, HangingNotice)
	<-ctx.Done()
	if err := os.WriteFile(marker, []byte("cancelled"), 0o600); err != nil {
		return nil, mcpwire.InternalError(err.Error())
	}
	return textResult("cancelled", false)
}

func textResult(text string, isError bool) (json.RawMessage, error) {
	return json.Marshal(map[string]any{
		"content": []map[string]string{{"type": "text", "text": text}},
		"isError": isError,
	})
}
