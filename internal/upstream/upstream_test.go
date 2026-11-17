package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/rawjson"
)

func toolNamesOf(t *testing.T, items []json.RawMessage) []string {
	t.Helper()
	var names []string
	for _, item := range items {
		name, ok := rawjson.String(item, "name")
		if !ok {
			t.Fatalf("tool without a name: %s", item)
		}
		names = append(names, name)
	}
	return names
}

func TestListsTheToolsOfAChildProcess(t *testing.T) {
	u := newUpstream(t, Config{Connector: fakeConnector(nil, nil)})
	listed, err := u.Tools(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(toolNamesOf(t, listed.Items), ",")
	if got != "echo,env,fail,die,hang" {
		t.Errorf("tools = %s", got)
	}
}

func TestPeerReusesTheConnection(t *testing.T) {
	connector := &pipeConnector{methods: func(string, json.RawMessage) (json.RawMessage, error) { return toolList("a"), nil }}
	u := newUpstream(t, Config{Connector: connector})
	for range 3 {
		if _, err := u.Peer(testContext(t)); err != nil {
			t.Fatal(err)
		}
	}
	if got := connector.connects.Load(); got != 1 {
		t.Errorf("connects = %d", got)
	}
}

func TestListTimeoutIsRememberedUntilTheRetryTime(t *testing.T) {
	clock := newFakeClock()
	connector := &hangConnector{}
	u := newUpstream(t, Config{
		Connector:   connector,
		ListTimeout: 50 * time.Millisecond,
		RetryAfter:  30 * time.Second,
		Now:         clock.Now,
	})
	_, err := u.ListPeer(testContext(t))
	if err == nil || err.Error() != "no connection within 0.05s" {
		t.Fatalf("err = %v", err)
	}

	clock.Advance(29 * time.Second)
	_, err = u.ListPeer(testContext(t))
	if err == nil || err.Error() != "no connection within 0.05s" {
		t.Fatalf("err = %v", err)
	}
	if got := connector.connects.Load(); got != 1 {
		t.Errorf("connects = %d, want the failure to be remembered", got)
	}

	clock.Advance(2 * time.Second)
	_, _ = u.ListPeer(testContext(t))
	if got := connector.connects.Load(); got != 2 {
		t.Errorf("connects = %d, want one more try after the retry time", got)
	}
}

func TestListTimeoutNamesTheSecondsLikeRust(t *testing.T) {
	u := newUpstream(t, Config{Connector: &hangConnector{}, ListTimeout: 1500 * time.Millisecond})
	_, err := u.ListPeer(testContext(t))
	if err == nil || err.Error() != "no connection within 1.5s" {
		t.Errorf("err = %v", err)
	}
}

func TestConnectTimeoutFailsTheUpstream(t *testing.T) {
	u := newUpstream(t, Config{
		Connector:      &hangConnector{},
		ConnectTimeout: 1 * time.Second,
		ListTimeout:    time.Minute,
	})
	_, err := u.Peer(testContext(t))
	if err == nil || err.Error() != "no response within 1s" {
		t.Errorf("err = %v", err)
	}
	_, err = u.Peer(testContext(t))
	if err == nil || err.Error() != "no response within 1s" {
		t.Errorf("the failure was not remembered: %v", err)
	}
}

func TestEndedContextGivesUpWithoutRecordingAFailure(t *testing.T) {
	connector := &hangConnector{}
	u := newUpstream(t, Config{Connector: connector})
	ctx, cancel := context.WithCancel(testContext(t))
	cancel()
	if _, err := u.Peer(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	pipe := &pipeConnector{methods: func(string, json.RawMessage) (json.RawMessage, error) { return nil, nil }}
	u.connector = pipe
	if _, err := u.Peer(testContext(t)); err != nil {
		t.Errorf("a cancelled request must not fail the upstream: %v", err)
	}
}

func TestClosedUpstreamRefusesAtOnce(t *testing.T) {
	connector := &hangConnector{}
	u := newUpstream(t, Config{Connector: connector})
	u.Shutdown()
	began := time.Now()
	_, err := u.Peer(testContext(t))
	if err == nil || err.Error() != "proxy is shutting down" {
		t.Errorf("err = %v", err)
	}
	if time.Since(began) > time.Second || connector.connects.Load() != 0 {
		t.Error("a closed upstream tried to connect")
	}
}

func TestReconnectsAfterTheChildDies(t *testing.T) {
	u := newUpstream(t, Config{Connector: fakeConnector(nil, nil)})
	first, err := u.Peer(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = first.Call(testContext(t), "tools/call", json.RawMessage(`{"name":"die"}`))
	if err == nil {
		t.Fatal("die should end the connection")
	}
	<-first.Peer.Done()

	second, err := u.Peer(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Error("the dead connection was reused")
	}
}

func TestToolMapAndRenamesLogOnlyWhenTheyChange(t *testing.T) {
	long := strings.Repeat("x", 60)
	tools := toolList("plain", long)
	connector := &pipeConnector{methods: func(string, json.RawMessage) (json.RawMessage, error) { return tools, nil }}
	var log syncBuffer
	u := newUpstream(t, Config{Connector: connector, Log: &log})

	listed, err := u.Tools(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	names := toolNamesOf(t, listed.Items)
	if names[0] != "plain" || names[1] == long || len(names[1]) > 49-len("fake__") {
		t.Fatalf("names = %q", names)
	}
	first := log.String()
	if strings.Count(first, "is exposed as") != 1 || !strings.Contains(first, `toolward: tool "`+long+`" of "fake" is exposed as "fake__`) {
		t.Errorf("log = %q", first)
	}

	if _, err := u.Tools(testContext(t)); err != nil {
		t.Fatal(err)
	}
	if log.String() != first {
		t.Errorf("an unchanged list logged again: %q", log.String())
	}

	pairs := u.ToolNames()
	if len(pairs) != 2 || pairs[0].Exposed > pairs[1].Exposed {
		t.Errorf("pairs = %+v", pairs)
	}
}

func TestDuplicateToolIsKeptOnce(t *testing.T) {
	connector := &pipeConnector{methods: func(string, json.RawMessage) (json.RawMessage, error) {
		return toolList("same", "same", "other"), nil
	}}
	u := newUpstream(t, Config{Connector: connector})
	listed, err := u.Tools(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(toolNamesOf(t, listed.Items), ","); got != "same,other" {
		t.Errorf("tools = %s", got)
	}
}

func TestOriginalToolAcceptsBothNamesAndListsAgainWhenUnknown(t *testing.T) {
	long := strings.Repeat("y", 60)
	lists := 0
	connector := &pipeConnector{methods: func(string, json.RawMessage) (json.RawMessage, error) {
		lists++
		return toolList("plain", long), nil
	}}
	u := newUpstream(t, Config{Connector: connector})

	original, ok, err := u.OriginalTool(testContext(t), long)
	if err != nil || !ok || original != long {
		t.Fatalf("by original name: %q %v %v", original, ok, err)
	}
	exposed := u.ToolNames()[1].Exposed
	original, ok, err = u.OriginalTool(testContext(t), exposed)
	if err != nil || !ok || original != long {
		t.Fatalf("by exposed name: %q %v %v", original, ok, err)
	}
	if lists != 1 {
		t.Errorf("lists = %d, want the known names to need none", lists)
	}
	if _, ok, err := u.OriginalTool(testContext(t), "unknown"); err != nil || ok {
		t.Errorf("unknown tool: %v %v", ok, err)
	}
	if lists != 2 {
		t.Errorf("lists = %d, want one more for the unknown name", lists)
	}
}

func TestToolListChangedForgetsTheMapAndIsForwarded(t *testing.T) {
	ready := make(chan *mcpwire.Peer, 1)
	connector := &pipeConnector{
		methods: func(string, json.RawMessage) (json.RawMessage, error) { return toolList("a"), nil },
	}
	connector.onInitialized = func(peer *mcpwire.Peer) { ready <- peer }
	hub := &Hub{}
	forwarded := make(chan string, 4)
	downstream := newNotificationPeer(t, forwarded)
	hub.SetDownstream(downstream)
	u := newUpstream(t, Config{Connector: connector, Hub: hub})
	if _, err := u.Tools(testContext(t)); err != nil {
		t.Fatal(err)
	}
	if len(u.ToolNames()) != 1 {
		t.Fatal("no tool map")
	}

	peer := <-ready
	if err := peer.Notify("notifications/tools/list_changed", nil); err != nil {
		t.Fatal(err)
	}
	if got := <-forwarded; got != "notifications/tools/list_changed" {
		t.Errorf("forwarded %q", got)
	}
	if len(u.ToolNames()) != 0 {
		t.Error("the tool map was kept")
	}
}

func TestStderrIsRelayedWithSecretsMasked(t *testing.T) {
	secrets := map[string]string{"token": "super-secret-value"}
	var log syncBuffer
	connector := &StdioConnector{
		Name: "noisy",
		Spec: StdioSpec{
			Command: "sh",
			Args:    []string{"-c", `echo "oops $TOKEN  " >&2; exit 1`},
			Env:     map[string]string{"TOKEN": "${keychain:token}"},
		},
		Store: memoryWith(secrets),
		Log:   &log,
	}
	u := newUpstream(t, Config{Connector: connector, Name: "noisy"})
	_, err := u.Peer(testContext(t))
	if err == nil || !strings.HasPrefix(err.Error(), "handshake failed: ") {
		t.Fatalf("err = %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(log.String(), "[noisy] oops") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := log.String(); got != "[noisy] oops [REDACTED]\n" {
		t.Errorf("log = %q", got)
	}
}

func TestStartFailureNamesTheCommand(t *testing.T) {
	connector := &StdioConnector{
		Spec:  StdioSpec{Command: "/nonexistent/toolward-test"},
		Store: memoryWith(nil),
	}
	u := newUpstream(t, Config{Connector: connector})
	_, err := u.Peer(testContext(t))
	if err == nil || !strings.HasPrefix(err.Error(), `cannot start "/nonexistent/toolward-test": `) {
		t.Errorf("err = %v", err)
	}
}

func TestRedactResultMasksTheSecretsOfTheConnection(t *testing.T) {
	connector := fakeConnector(nil, map[string]string{"FAKE_SECRET": "${keychain:token}"})
	connector.Store = memoryWith(map[string]string{"token": "hunter2-secret"})
	u := newUpstream(t, Config{Connector: connector})
	if _, err := u.Peer(testContext(t)); err != nil {
		t.Fatal(err)
	}
	got, err := u.RedactResult(json.RawMessage(`{"text":"x hunter2-secret y"}`))
	if err != nil || string(got) != `{"text":"x [REDACTED] y"}` {
		t.Errorf("got %s, %v", got, err)
	}
	if got := u.Redact("a hunter2-secret b"); got != "a [REDACTED] b" {
		t.Errorf("redact = %q", got)
	}
	u.handler.AddSecrets([]string{"later-secret"})
	if got := u.Redact("later-secret"); got != "[REDACTED]" {
		t.Errorf("added secret not masked: %q", got)
	}
}

func TestBoundedGivesUpAfterTheListTimeout(t *testing.T) {
	u := newUpstream(t, Config{Connector: &hangConnector{}, ListTimeout: 50 * time.Millisecond})
	_, err := Bounded(testContext(t), u, func(ctx context.Context) (int, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	})
	if err == nil || err.Error() != "no response to a list request within 0.05s" {
		t.Errorf("err = %v", err)
	}
}

func TestBoundedRedactsErrors(t *testing.T) {
	u := newUpstream(t, Config{Connector: &hangConnector{}})
	u.handler.RememberSecrets([]string{"leaky-secret"})
	_, err := Bounded(testContext(t), u, func(context.Context) (int, error) {
		return 0, errors.New("boom leaky-secret")
	})
	if err == nil || err.Error() != "boom [REDACTED]" {
		t.Errorf("err = %v", err)
	}
}
