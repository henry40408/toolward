package check

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/proxy"
	"github.com/henry40408/toolward/internal/store"
	"github.com/henry40408/toolward/internal/testing/httpfake"
	"github.com/henry40408/toolward/internal/upstream"
)

const longTool = "create_pull_request_review_comment_thread_reply"

func httpUpstream(name, url string, hub *upstream.Hub, log *bytes.Buffer) *upstream.Upstream {
	return upstream.New(upstream.Config{
		Name:      name,
		Connector: &upstream.HTTPConnector{Spec: upstream.HTTPSpec{URL: url}, Store: store.NewMemory()},
		Hub:       hub,
		Log:       log,
	})
}

func TestCheckToolsListsExposedNamesAndFlagsFailures(t *testing.T) {
	fast := httpfake.New(t, "ping", longTool)
	hub := &upstream.Hub{}
	log := &bytes.Buffer{}
	p := proxy.New(proxy.Options{Hub: hub, Log: log, Upstreams: []*upstream.Upstream{
		httpUpstream("down", "http://127.0.0.1:1/mcp", hub, log),
		httpUpstream("fast", fast.URL, hub, log),
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	reports := CheckTools(ctx, p, nil)

	if AllOK(reports) {
		t.Error("AllOK = true")
	}
	text := textOf(t, reports, TextOptions{ToolsChecked: true})
	for _, want := range []string{
		"fast__ping",
		"fake-http 0",
		"prompts, resources, tools",
		"✓ 2 tools",
		"(renamed from " + `"` + longTool + `")`,
		"✗ tools unavailable",
		"1 with problem",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	assertToolsJSON(t, reports)
}

func assertToolsJSON(t *testing.T, reports []*ServerReport) {
	t.Helper()
	_, document := jsonOf(t, reports)
	if document["ok"] != false {
		t.Errorf("ok = %v", document["ok"])
	}
	servers := map[string]map[string]any{}
	for _, server := range document["servers"].([]any) {
		entry := server.(map[string]any)
		servers[entry["name"].(string)] = entry["upstream"].(map[string]any)
	}
	fast := servers["fast"]
	if fast["status"] != "ok" || fast["server"] != "fake-http 0" {
		t.Errorf("fast = %v", fast)
	}
	if got := fast["capabilities"].([]any); len(got) != 3 || got[0] != "prompts" || got[1] != "resources" || got[2] != "tools" {
		t.Errorf("capabilities = %v", got)
	}
	assertFastTools(t, fast["tools"].([]any))
	down := servers["down"]
	if reason, isString := down["reason"].(string); down["status"] != "error" || !isString || reason == "" {
		t.Errorf("down = %v", down)
	}
}

func assertFastTools(t *testing.T, tools []any) {
	t.Helper()
	var sawPing, sawRenamed bool
	for _, tool := range tools {
		entry := tool.(map[string]any)
		sawPing = sawPing || (entry["name"] == "fast__ping" && entry["original"] == "ping")
		sawRenamed = sawRenamed || (entry["original"] == longTool && entry["name"] != "fast__"+longTool)
	}
	if !sawPing || !sawRenamed {
		t.Errorf("tools = %v", tools)
	}
}
