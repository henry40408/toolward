package fakeupstream

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/mcpwire"
)

func TestMain(m *testing.M) {
	if os.Getenv(EnvSwitch) == "1" {
		Run()
		return
	}
	os.Exit(m.Run())
}

func start(t *testing.T, env ...string) *mcpwire.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	transport, err := mcpwire.StartCommand(ctx, mcpwire.CommandConfig{
		Path:     os.Args[0],
		ExtraEnv: append([]string{EnvSwitch + "=1"}, env...),
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := mcpwire.NewPeer(transport, nil)
	t.Cleanup(func() { _ = peer.Close() })
	session, err := mcpwire.Initialize(ctx, peer, mcpwire.Implementation{Name: "test", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func call(t *testing.T, session *mcpwire.Session, method, params string) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	raw, err := session.Call(ctx, method, json.RawMessage(params))
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func toolText(result map[string]any) string {
	content := result["content"].([]any)
	return content[0].(map[string]any)["text"].(string)
}

func TestListsTheFiveToolsWithoutCacheHints(t *testing.T) {
	result := call(t, start(t), "tools/list", `{}`)
	var names []string
	for _, tool := range result["tools"].([]any) {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	if got := strings.Join(names, ","); got != "echo,env,fail,die,hang" {
		t.Errorf("tools = %s", got)
	}
	for _, key := range []string{"ttlMs", "cacheScope"} {
		if _, ok := result[key]; ok {
			t.Errorf("the list carries %s", key)
		}
	}
}

func TestCacheHintsComeFromTheEnvironment(t *testing.T) {
	result := call(t, start(t, "FAKE_TTL_MS=60000", "FAKE_CACHE_SCOPE=public"), "tools/list", `{}`)
	if result["ttlMs"] != float64(60000) || result["cacheScope"] != "public" {
		t.Errorf("hints = %v %v", result["ttlMs"], result["cacheScope"])
	}
}

func TestToolCalls(t *testing.T) {
	session := start(t, "FAKE_SECRET=s3cret")
	echo := call(t, session, "tools/call", `{"name":"echo","arguments":{"text":"hi"}}`)
	if toolText(echo) != "echo: hi" || echo["isError"] != false {
		t.Errorf("echo = %v", echo)
	}
	env := call(t, session, "tools/call", `{"name":"env","arguments":{"name":"FAKE_SECRET"}}`)
	if toolText(env) != "s3cret" {
		t.Errorf("env = %v", env)
	}
	unset := call(t, session, "tools/call", `{"name":"env","arguments":{"name":"FAKE_NOT_SET"}}`)
	if toolText(unset) != "<unset>" {
		t.Errorf("unset = %v", unset)
	}
	fail := call(t, session, "tools/call", `{"name":"fail"}`)
	if toolText(fail) != "boom" || fail["isError"] != true {
		t.Errorf("fail = %v", fail)
	}
}

func TestUnknownToolIsRefused(t *testing.T) {
	session := start(t)
	_, err := session.Call(context.Background(), "tools/call", json.RawMessage(`{"name":"nope"}`))
	var rpcErr *mcpwire.Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != mcpwire.CodeInvalidParams {
		t.Errorf("err = %v", err)
	}
}

func TestNoToolsAnnouncesPromptsAndRefusesTheList(t *testing.T) {
	session := start(t, "FAKE_NO_TOOLS=1")
	if got := string(session.Info.Capabilities); got != `{"prompts":{}}` {
		t.Errorf("capabilities = %s", got)
	}
	_, err := session.Call(context.Background(), "tools/list", json.RawMessage(`{}`))
	var rpcErr *mcpwire.Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != mcpwire.CodeMethodNotFound {
		t.Errorf("err = %v", err)
	}
}

func TestListDelay(t *testing.T) {
	session := start(t, "FAKE_LIST_DELAY_MS=300")
	began := time.Now()
	call(t, session, "tools/list", `{}`)
	if elapsed := time.Since(began); elapsed < 300*time.Millisecond {
		t.Errorf("listing took %v", elapsed)
	}
}

func TestHangWritesTheMarkerWhenCancelled(t *testing.T) {
	session := start(t)
	marker := filepath.Join(t.TempDir(), "marker")
	params, _ := json.Marshal(map[string]any{"name": "hang", "arguments": map[string]string{"marker": marker}})

	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		_, err := session.Call(ctx, "tools/call", params)
		errs <- err
	}()
	time.Sleep(200 * time.Millisecond) // lets the call reach the fake
	cancel()
	if err := <-errs; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(marker); err == nil {
			if string(data) != "cancelled" {
				t.Errorf("marker = %q", data)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("marker was not written")
}

func TestDieEndsTheConnection(t *testing.T) {
	session := start(t)
	_, err := session.Call(context.Background(), "tools/call", json.RawMessage(`{"name":"die"}`))
	if !errors.Is(err, mcpwire.ErrClosed) {
		t.Errorf("err = %v", err)
	}
	select {
	case <-session.Peer.Done():
	case <-time.After(10 * time.Second):
		t.Error("the connection stayed open")
	}
}
