// Package httpfake is an MCP server over plain HTTP for tests. It answers each
// POST with one JSON body, like a server that never streams.
package httpfake

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

// Request is what the fake saw of one HTTP request.
type Request struct {
	Method string
	Header http.Header
}

// Fake is one running server.
type Fake struct {
	// URL is the endpoint to point an upstream at.
	URL string

	server *httptest.Server
	done   chan struct{}
	silent bool

	mu             sync.Mutex
	tools          []string
	requests       []Request
	versions       []string
	failStatus     int
	discoverStatus int
}

// New starts a fake that lists the given tools. The server stops with the test.
func New(t *testing.T, tools ...string) *Fake {
	t.Helper()
	return start(t, &Fake{tools: tools})
}

// NewSilent starts a fake that accepts requests and never answers them.
func NewSilent(t *testing.T) *Fake {
	t.Helper()
	return start(t, &Fake{silent: true})
}

func start(t *testing.T, fake *Fake) *Fake {
	t.Helper()
	fake.done = make(chan struct{})
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serve))
	fake.URL = fake.server.URL + "/mcp"
	t.Cleanup(func() {
		close(fake.done)
		fake.server.CloseClientConnections()
		fake.server.Close()
	})
	return fake
}

// SetTools replaces the listed tools.
func (f *Fake) SetTools(tools ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tools = tools
}

// FailWith answers every request with the status and a body that echoes the
// Authorization header, so tests can check that errors are redacted. Zero
// restores normal answers.
func (f *Fake) FailWith(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failStatus = status
}

// DiscoverStatus makes server/discover answer with an HTTP status instead of
// a JSON-RPC error. Zero restores the JSON-RPC error.
func (f *Fake) DiscoverStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discoverStatus = status
}

// Versions returns the protocolVersion of each initialize request, in order.
func (f *Fake) Versions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.versions...)
}

// Requests returns every request the fake received, in order.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.requests...)
}

// Authorizations returns the Authorization header of each request, in order.
func (f *Fake) Authorizations() []string {
	var headers []string
	for _, request := range f.Requests() {
		headers = append(headers, request.Header.Get("Authorization"))
	}
	return headers
}

type rpcMessage struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params map[string]any  `json:"params"`
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	failStatus := f.record(r)
	if f.silent {
		<-f.done
		return
	}
	if failStatus != 0 {
		reply(w, failStatus, "rejected "+r.Header.Get("Authorization"))
		return
	}
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, "")
		return
	}
	body, _ := io.ReadAll(r.Body)
	var message rpcMessage
	_ = json.Unmarshal(body, &message)
	if len(message.ID) == 0 {
		reply(w, http.StatusAccepted, "")
		return
	}
	f.answer(w, message, r.Header.Get("Authorization"))
}

// record stores the request and returns the failure status in force.
func (f *Fake) record(r *http.Request) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, Request{Method: r.Method, Header: r.Header.Clone()})
	return f.failStatus
}

func (f *Fake) answer(w http.ResponseWriter, message rpcMessage, authorization string) {
	if message.Method == "server/discover" {
		f.answerDiscover(w, message.ID)
		return
	}
	result := f.resultFor(message, authorization)
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": result})
	reply(w, http.StatusOK, string(body))
}

// answerDiscover plays a server from before 2026-07-28.
func (f *Fake) answerDiscover(w http.ResponseWriter, id json.RawMessage) {
	f.mu.Lock()
	status := f.discoverStatus
	f.mu.Unlock()
	if status != 0 {
		reply(w, status, "unavailable")
		return
	}
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": -32601, "message": "Method not found"},
	})
	reply(w, http.StatusOK, string(body))
}

func (f *Fake) resultFor(message rpcMessage, authorization string) any {
	params := message.Params
	switch message.Method {
	case "initialize":
		return f.initialize(params)
	case "tools/list":
		return map[string]any{"tools": f.toolList()}
	case "tools/call":
		return toolCall(params, authorization)
	case "resources/list":
		return map[string]any{"resources": []map[string]any{{"uri": "file:///a b/notes.txt?x=1", "name": "notes"}}}
	case "resources/read":
		return map[string]any{"contents": []map[string]any{
			{"uri": params["uri"], "mimeType": "text/plain", "text": "hello" + authorization},
		}}
	case "prompts/list":
		return map[string]any{"prompts": []map[string]any{{"name": "greet"}}}
	case "prompts/get":
		name, _ := params["name"].(string)
		return map[string]any{"messages": []map[string]any{{
			"role":    "user",
			"content": map[string]any{"type": "text", "text": "prompt " + name + authorization},
		}}}
	}
	return nil
}

func (f *Fake) initialize(params map[string]any) map[string]any {
	version, _ := params["protocolVersion"].(string)
	f.mu.Lock()
	f.versions = append(f.versions, version)
	f.mu.Unlock()
	return map[string]any{
		"protocolVersion": params["protocolVersion"],
		"capabilities":    map[string]any{"tools": map[string]any{}, "resources": map[string]any{}, "prompts": map[string]any{}},
		"serverInfo":      map[string]any{"name": "fake-http", "version": "0"},
	}
}

func (f *Fake) toolList() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	tools := make([]map[string]any, 0, len(f.tools))
	for _, name := range f.tools {
		tools = append(tools, map[string]any{"name": name, "inputSchema": map[string]any{"type": "object"}})
	}
	return tools
}

// toolCall answers whoami with the Authorization header the fake saw.
func toolCall(params map[string]any, authorization string) map[string]any {
	name, _ := params["name"].(string)
	text := "called " + name
	if name == "whoami" {
		text = authorization
	}
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": text}},
		"structuredContent": map[string]any{"seen": authorization},
	}
}

func reply(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
