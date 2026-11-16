package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/store"
	"github.com/henry40408/toolward/internal/testing/fakeupstream"
	"github.com/henry40408/toolward/internal/upstream"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakeupstream.EnvSwitch) == "1" {
		fakeupstream.Run()
		return
	}
	os.Exit(m.Run())
}

// syncBuffer is a log that tests can read while the code writes to it.
type syncBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String()
}

// fakeServer describes one upstream that runs this test binary as the fake.
type fakeServer struct {
	name        string
	command     string
	env         map[string]string
	listTimeout time.Duration
}

// fake is a working upstream that runs this test binary.
func fake(name string, env map[string]string) fakeServer {
	return fakeServer{name: name, command: os.Args[0], env: env}
}

func (s fakeServer) build(hub *upstream.Hub, secrets store.Store, log io.Writer) *upstream.Upstream {
	env := map[string]string{fakeupstream.EnvSwitch: "1"}
	for key, value := range s.env {
		env[key] = value
	}
	return upstream.New(upstream.Config{
		Name: s.name,
		Connector: &upstream.StdioConnector{
			Name:  s.name,
			Spec:  upstream.StdioSpec{Command: s.command, Env: env},
			Store: secrets,
			Log:   log,
		},
		Hub:         hub,
		Log:         log,
		ListTimeout: s.listTimeout,
	})
}

// harness is a proxy and an agent connected to it.
type harness struct {
	t      *testing.T
	proxy  *Proxy
	client *mcpwire.Session
	log    *syncBuffer
}

func newProxy(servers []fakeServer, secrets map[string]string) (*Proxy, *syncBuffer) {
	hub := &upstream.Hub{}
	log := &syncBuffer{}
	var upstreams []*upstream.Upstream
	for _, server := range servers {
		upstreams = append(upstreams, server.build(hub, store.NewMemoryWith(secrets), log))
	}
	return New(Options{Hub: hub, Upstreams: upstreams, Log: log}), log
}

// start connects an agent that uses the 2026-07-28 protocol, with no
// handshake.
func start(t *testing.T, servers ...fakeServer) *harness {
	t.Helper()
	return startWith(t, nil, mcpwire.Discover, servers...)
}

// startLegacy connects an agent that uses the initialize handshake.
func startLegacy(t *testing.T, servers ...fakeServer) *harness {
	t.Helper()
	return startWith(t, nil, mcpwire.Initialize, servers...)
}

type connectFunc func(context.Context, *mcpwire.Peer, mcpwire.Implementation) (*mcpwire.Session, error)

func startWith(t *testing.T, secrets map[string]string, connect connectFunc, servers ...fakeServer) *harness {
	t.Helper()
	proxy, log := newProxy(servers, secrets)
	return connectAgent(t, proxy, log, connect)
}

func connectAgent(t *testing.T, proxy *Proxy, log *syncBuffer, connect connectFunc) *harness {
	t.Helper()
	agentRead, proxyWrite := io.Pipe()
	proxyRead, agentWrite := io.Pipe()
	serving := proxy.Serve(mcpwire.NewStdioTransport(proxyRead, proxyWrite))
	agent := mcpwire.NewPeer(mcpwire.NewStdioTransport(agentRead, agentWrite), nil)
	t.Cleanup(func() {
		_ = agent.Close()
		_ = serving.Close()
		proxy.Shutdown()
	})
	session, err := connect(testContext(t), agent, mcpwire.Implementation{Name: "agent", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, proxy: proxy, client: session, log: log}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// request sends a request and returns the raw result or the error.
func (h *harness) request(method, params string) (json.RawMessage, error) {
	h.t.Helper()
	return h.client.Call(testContext(h.t), method, json.RawMessage(params))
}

func (h *harness) mustRequest(method, params string) json.RawMessage {
	h.t.Helper()
	raw, err := h.request(method, params)
	if err != nil {
		h.t.Fatalf("%s: %v", method, err)
	}
	return raw
}

// listed is a list result as the agent sees it.
type listed struct {
	Tools      []map[string]any `json:"tools"`
	TTLMs      *uint64          `json:"ttlMs"`
	CacheScope *string          `json:"cacheScope"`
}

func (h *harness) listTools() listed {
	h.t.Helper()
	var result listed
	if err := json.Unmarshal(h.mustRequest("tools/list", `{}`), &result); err != nil {
		h.t.Fatal(err)
	}
	return result
}

func (h *harness) toolNames() []string {
	h.t.Helper()
	var names []string
	for _, tool := range h.listTools().Tools {
		names = append(names, tool["name"].(string))
	}
	return names
}

func (h *harness) callTool(name, arguments string) (json.RawMessage, error) {
	h.t.Helper()
	return h.request("tools/call", `{"name":"`+name+`","arguments":`+arguments+`}`)
}
