package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/testing/fakeupstream"
)

var fakeTools = []string{"fake__die", "fake__echo", "fake__env", "fake__fail", "fake__hang"}

func mustText(t *testing.T, raw json.RawMessage, err error) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestListsPrefixedToolsAndForwardsCalls(t *testing.T) {
	h := start(t, fake("fake", nil))

	if got := h.toolNames(); !slices.Equal(got, fakeTools) {
		t.Fatalf("tools = %v", got)
	}
	raw, err := h.callTool("fake__echo", `{"text":"hi"}`)
	if text := mustText(t, raw, err); !strings.Contains(text, "echo: hi") {
		t.Errorf("result = %s", text)
	}
}

func TestToolLevelErrorsPassThrough(t *testing.T) {
	h := start(t, fake("fake", nil))

	raw, err := h.callTool("fake__fail", `{}`)
	text := mustText(t, raw, err)
	if !strings.Contains(text, `"isError":true`) || !strings.Contains(text, "boom") {
		t.Errorf("result = %s", text)
	}
}

func TestSecretsReachTheChildEnvironmentOnly(t *testing.T) {
	env := map[string]string{"FAKE_SECRET": "${keychain:tok}", "FAKE_PLAIN": "plain"}
	h := startWith(t, map[string]string{"tok": "s3cr3t-value"}, mcpwire.Discover, fake("fake", env))

	// The child sees the expanded value, but what it echoes back is masked.
	raw, err := h.callTool("fake__env", `{"name":"FAKE_SECRET"}`)
	echoed := mustText(t, raw, err)
	if !strings.Contains(echoed, "[REDACTED]") || strings.Contains(echoed, "s3cr3t-value") {
		t.Errorf("echoed = %s", echoed)
	}
	raw, err = h.callTool("fake__env", `{"name":"FAKE_PLAIN"}`)
	if text := mustText(t, raw, err); !strings.Contains(text, "plain") {
		t.Errorf("plain = %s", text)
	}
	listing, err := json.Marshal(h.listTools())
	if err != nil || strings.Contains(string(listing), "s3cr3t-value") {
		t.Errorf("the tool list carries the secret: %s, %v", listing, err)
	}
}

func TestFailingUpstreamsAreSkipped(t *testing.T) {
	h := start(t,
		fakeServer{name: "broken", command: "/nonexistent/toolward-test-binary"},
		fake("fake", nil),
		// References a secret that is not stored.
		fake("nosecret", map[string]string{"X": "${keychain:absent}"}),
	)

	if got := h.toolNames(); !slices.Equal(got, fakeTools) {
		t.Fatalf("tools = %v", got)
	}
	_, err := h.callTool("broken__echo", `{}`)
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("broken: %v", err)
	}
	_, err = h.callTool("nosecret__echo", `{}`)
	if err == nil || !strings.Contains(err.Error(), "absent") {
		t.Errorf("nosecret: %v", err)
	}
}

func TestASlowListingIsSkipped(t *testing.T) {
	slow := fake("slow", map[string]string{"FAKE_LIST_DELAY_MS": "30000"})
	slow.listTimeout = 1500 * time.Millisecond
	h := start(t, slow, fake("fast", nil))

	started := time.Now()
	names := h.toolNames()
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Errorf("listing took %v", elapsed)
	}
	if len(names) == 0 {
		t.Fatal("no tools")
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "fast__") {
			t.Errorf("unexpected tool %q", name)
		}
	}
}

func TestCancellingACallCancelsItUpstream(t *testing.T) {
	h := start(t, fake("fake", nil))
	marker := filepath.Join(t.TempDir(), "marker")
	params, _ := json.Marshal(map[string]any{"name": "fake__hang", "arguments": map[string]string{"marker": marker}})

	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		_, err := h.client.Call(ctx, "tools/call", params)
		errs <- err
	}()
	waitForLog(t, h, "[fake] "+fakeupstream.HangingNotice)
	cancel()
	if err := <-errs; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	waitForFile(t, marker)
}

func waitForLog(t *testing.T, h *harness, want string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(h.log.String(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("log never held %q:\n%s", want, h.log.String())
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the upstream never saw the cancellation")
}

func TestReconnectsAfterTheUpstreamProcessDies(t *testing.T) {
	h := start(t, fake("fake", nil))

	if _, err := h.callTool("fake__echo", `{"text":"a"}`); err != nil {
		t.Fatal(err)
	}
	// The child exits without answering.
	if _, err := h.callTool("fake__die", `{}`); err == nil {
		t.Fatal("die answered")
	}
	// The next call may race with the proxy noticing the exit; it must recover.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := h.callTool("fake__echo", `{"text":"b"}`)
		if err == nil {
			if !strings.Contains(string(raw), "echo: b") {
				t.Fatalf("result = %s", raw)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("upstream was never reconnected")
}

func TestUnknownToolsAreRejected(t *testing.T) {
	h := start(t, fake("fake", nil))

	for _, name := range []string{"echo", "nope__echo", "fake__nope"} {
		_, err := h.callTool(name, `{}`)
		var rpcErr *mcpwire.Error
		if !errors.As(err, &rpcErr) || rpcErr.Code != mcpwire.CodeInvalidParams {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// hintsOf returns the hints of the tool list the agent receives.
func hintsOf(t *testing.T, h *harness) (ttl uint64, scope string) {
	t.Helper()
	list := h.listTools()
	if list.TTLMs == nil || list.CacheScope == nil {
		t.Fatalf("the list has no hints: %+v", list)
	}
	return *list.TTLMs, *list.CacheScope
}

func expectHints(t *testing.T, h *harness, wantTTL uint64, wantScope string) {
	t.Helper()
	if ttl, scope := hintsOf(t, h); ttl != wantTTL || scope != wantScope {
		t.Errorf("hints = %d, %s; want %d, %s", ttl, scope, wantTTL, wantScope)
	}
}

var publicMinute = map[string]string{"FAKE_TTL_MS": "60000", "FAKE_CACHE_SCOPE": "public"}

func TestAListWithoutHintsIsUncacheable(t *testing.T) {
	expectHints(t, start(t, fake("fake", nil)), 0, "private")
}

func TestTheHintsOfOneUpstreamReachTheAgent(t *testing.T) {
	expectHints(t, start(t, fake("fake", publicMinute)), 60000, "public")
}

func TestMergedListsGetTheWeakestHint(t *testing.T) {
	shortPrivate := map[string]string{"FAKE_TTL_MS": "5000", "FAKE_CACHE_SCOPE": "private"}
	h := start(t, fake("a", publicMinute), fake("b", shortPrivate))
	expectHints(t, h, 5000, "private")
}

func TestAListMissingAnUpstreamIsNotCacheable(t *testing.T) {
	h := start(t,
		fake("fake", publicMinute),
		fakeServer{name: "broken", command: "/nonexistent/toolward-test-binary"},
	)
	expectHints(t, h, 0, "private")
}

func TestAnUpstreamWithoutToolsDoesNotLimitTheHint(t *testing.T) {
	h := start(t, fake("fake", publicMinute), fake("promptsonly", map[string]string{"FAKE_NO_TOOLS": "1"}))
	expectHints(t, h, 60000, "public")
}

func TestResourceTemplatesCarryHints(t *testing.T) {
	h := start(t, fake("fake", nil))

	var list struct {
		Templates  []json.RawMessage `json:"resourceTemplates"`
		TTLMs      uint64            `json:"ttlMs"`
		CacheScope string            `json:"cacheScope"`
	}
	if err := json.Unmarshal(h.mustRequest("resources/templates/list", `{}`), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Templates) != 0 || list.TTLMs != 0 || list.CacheScope != "private" {
		t.Errorf("list = %+v", list)
	}
}

func TestResultTypeIsCompleteForCurrentAgentsAndDroppedForLegacyOnes(t *testing.T) {
	current := start(t, fake("fake", nil))
	raw, err := current.callTool("fake__echo", `{"text":"x"}`)
	if text := mustText(t, raw, err); !strings.Contains(text, `"resultType":"complete"`) {
		t.Errorf("current agent: %s", text)
	}
	legacy := startLegacy(t, fake("fake", nil))
	raw, err = legacy.callTool("fake__echo", `{"text":"x"}`)
	if text := mustText(t, raw, err); strings.Contains(text, "resultType") {
		t.Errorf("legacy agent: %s", text)
	}
}

func TestLogNamesTheSkippedUpstream(t *testing.T) {
	h := start(t, fakeServer{name: "broken", command: "/nonexistent/toolward-test-binary"})
	h.listTools()
	if !strings.Contains(h.log.String(), `skipping upstream "broken"`) {
		t.Errorf("log = %s", h.log.String())
	}
}

func TestConcurrentCallsAreIndependent(t *testing.T) {
	h := start(t, fake("fake", nil))
	var group sync.WaitGroup
	for _, text := range []string{"one", "two", "three", "four"} {
		group.Add(1)
		go func() {
			defer group.Done()
			raw, err := h.callTool("fake__echo", `{"text":"`+text+`"}`)
			if err != nil || !strings.Contains(string(raw), "echo: "+text) {
				t.Errorf("%s: %s, %v", text, raw, err)
			}
		}()
	}
	group.Wait()
}
