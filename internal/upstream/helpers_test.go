package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/store"
	"github.com/henry40408/toolward/internal/testing/fakeupstream"
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

// fakeClock is a clock that moves when a test says so.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// fakeConnector starts the fake upstream, which is the test binary itself.
func fakeConnector(log io.Writer, env map[string]string) *StdioConnector {
	all := map[string]string{fakeupstream.EnvSwitch: "1"}
	for key, value := range env {
		all[key] = value
	}
	return &StdioConnector{
		Name:  "fake",
		Spec:  StdioSpec{Command: os.Args[0], Env: all},
		Store: store.NewMemory(),
		Log:   log,
	}
}

func newUpstream(t *testing.T, config Config) *Upstream {
	t.Helper()
	if config.Name == "" {
		config.Name = "fake"
	}
	if config.Hub == nil {
		config.Hub = &Hub{}
	}
	u := New(config)
	t.Cleanup(u.Shutdown)
	return u
}

type methodFunc func(method string, params json.RawMessage) (json.RawMessage, error)

func (f methodFunc) HandleRequest(_ context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	return f(method, params)
}

// pipeConnector connects to an in-process server.
type pipeConnector struct {
	methods       methodFunc
	capabilities  string
	connects      atomic.Int32
	onInitialized func(peer *mcpwire.Peer)
}

func (c *pipeConnector) Connect(ctx context.Context, handler *Handler) (*mcpwire.Session, error) {
	c.connects.Add(1)
	clientRead, serverWrite := io.Pipe()
	serverRead, clientWrite := io.Pipe()
	capabilities := c.capabilities
	if capabilities == "" {
		capabilities = `{"tools":{}}`
	}
	mcpwire.NewPeer(mcpwire.NewStdioTransport(serverRead, serverWrite), mcpwire.NewServer(mcpwire.ServerConfig{
		Info:          mcpwire.Implementation{Name: "pipe", Version: "0"},
		Capabilities:  json.RawMessage(capabilities),
		Methods:       c.methods,
		OnInitialized: c.onInitialized,
	}))
	peer := mcpwire.NewPeer(mcpwire.NewStdioTransport(clientRead, clientWrite), handler)
	return mcpwire.Initialize(ctx, peer, ClientInfo())
}

// hangConnector never connects; it waits until ctx ends.
type hangConnector struct{ connects atomic.Int32 }

func (c *hangConnector) Connect(ctx context.Context, _ *Handler) (*mcpwire.Session, error) {
	c.connects.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

func toolList(names ...string) json.RawMessage {
	tools := make([]string, 0, len(names))
	for _, name := range names {
		tools = append(tools, `{"name":"`+name+`","inputSchema":{"type":"object"}}`)
	}
	return json.RawMessage(`{"tools":[` + strings.Join(tools, ",") + `]}`)
}

func memoryWith(entries map[string]string) store.Store {
	return store.NewMemoryWith(entries)
}

// newNotificationPeer returns the peer a hub would hold for the agent. The
// methods of the notifications it receives go to received.
func newNotificationPeer(t *testing.T, received chan<- string) *mcpwire.Peer {
	t.Helper()
	agentRead, hubWrite := io.Pipe()
	hubRead, agentWrite := io.Pipe()
	agent := mcpwire.NewPeer(mcpwire.NewStdioTransport(agentRead, agentWrite), mcpwire.ClientHandler{
		OnNotification: func(method string, _ json.RawMessage) { received <- method },
	})
	hubSide := mcpwire.NewPeer(mcpwire.NewStdioTransport(hubRead, hubWrite), nil)
	t.Cleanup(func() {
		_ = agent.Close()
		_ = hubSide.Close()
	})
	return hubSide
}
