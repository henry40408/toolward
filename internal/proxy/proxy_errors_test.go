package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/henry40408/toolward/internal/config"
	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/store"
	"github.com/henry40408/toolward/internal/testing/fakeupstream"
	"github.com/henry40408/toolward/internal/upstream"
)

func rpcCode(t *testing.T, err error) int {
	t.Helper()
	var rpcErr *mcpwire.Error
	if !errors.As(err, &rpcErr) {
		t.Fatalf("not an MCP error: %v", err)
	}
	return rpcErr.Code
}

func TestFromConfigBuildsEveryServerInNameOrder(t *testing.T) {
	command, _ := json.Marshal(os.Args[0])
	text := fmt.Sprintf(`{"mcpServers":{
		"zulu":{"command":%[1]s,"env":{%[2]q:"1"}},
		"alpha":{"command":%[1]s,"env":{%[2]q:"1"}},
		"web":{"url":"http://127.0.0.1:1/mcp","headers":{"X-Key":"${keychain:web-key}"}},
		"login":{"url":"http://127.0.0.1:1/mcp","oauth":{}}
	}}`, command, fakeupstream.EnvSwitch)
	cfg, err := config.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	log := &syncBuffer{}
	proxy := FromConfig(FromConfigOptions{Config: cfg, Store: store.NewMemory(), Log: log})

	var order []string
	for _, u := range proxy.Upstreams() {
		order = append(order, u.Name())
	}
	if got := strings.Join(order, ","); got != "alpha,login,web,zulu" {
		t.Fatalf("upstreams %q", got)
	}

	h := connectAgent(t, proxy, log, mcpwire.Discover)
	names := h.toolNames()
	var fromAlpha, fromZulu bool
	for _, name := range names {
		fromAlpha = fromAlpha || strings.HasPrefix(name, "alpha__")
		fromZulu = fromZulu || strings.HasPrefix(name, "zulu__")
	}
	if !fromAlpha || !fromZulu {
		t.Fatalf("tools %v", names)
	}
}

func TestFromConfigSkipsAServerWithoutATransport(t *testing.T) {
	// The config package rejects such a server when it is parsed, so the
	// config here is built by hand.
	cfg := &config.Config{Servers: map[string]*config.ServerConfig{"empty": {}}}
	log := &syncBuffer{}
	proxy := FromConfig(FromConfigOptions{Config: cfg, Store: store.NewMemory(), Log: log})
	if got := len(proxy.Upstreams()); got != 0 {
		t.Fatalf("%d upstreams", got)
	}
	if !strings.Contains(log.String(), `toolward: skipping "empty": `) {
		t.Fatalf("log %q", log.String())
	}
}

func TestUnknownMethodsAreRefused(t *testing.T) {
	h := start(t, fake("one", nil))
	_, err := h.request("foo/bar", `{}`)
	if err == nil || rpcCode(t, err) != -32601 {
		t.Fatalf("err = %v", err)
	}
}

func TestReadingAResourceNeedsValidParamsAndAKnownServer(t *testing.T) {
	h := start(t, fake("one", nil))
	tests := []struct {
		name, params, want string
	}{
		{"a number for the uri", `{"uri":5}`, "invalid params"},
		{"another scheme", `{"uri":"https://example.com/x"}`, "unknown resource"},
		{"no path", `{"uri":"toolward://one"}`, "unknown resource"},
		{"a broken escape", `{"uri":"toolward://one/%zz"}`, "unknown resource"},
		{"an unknown server", `{"uri":"toolward://ghost/x"}`, "unknown resource"},
	}
	for _, test := range tests {
		_, err := h.request("resources/read", test.params)
		if err == nil || !strings.Contains(err.Error(), test.want) || rpcCode(t, err) != -32602 {
			t.Errorf("%s: err = %v", test.name, err)
		}
	}
}

func TestExposedReadRenamesEveryContentAndKeepsTheOthersAsTheyAre(t *testing.T) {
	result := json.RawMessage(`{"contents":[{"uri":"file:///a b","text":"x"},{"text":"no uri"}]}`)
	got, err := exposedRead("srv", result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		TTLMs      *int64 `json:"ttlMs"`
		CacheScope string `json:"cacheScope"`
		ResultType string `json:"resultType"`
		Contents   []struct {
			URI  string `json:"uri"`
			Text string `json:"text"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.TTLMs == nil || decoded.CacheScope == "" || decoded.ResultType != "complete" {
		t.Fatalf("hints missing in %s", got)
	}
	if decoded.Contents[0].URI != "toolward://srv/file%3A%2F%2F%2Fa%20b" || decoded.Contents[1].URI != "" || decoded.Contents[1].Text != "no uri" {
		t.Fatalf("contents %+v", decoded.Contents)
	}
}

func TestExposedReadRefusesContentsThatAreNotAList(t *testing.T) {
	_, err := exposedRead("srv", json.RawMessage(`{"contents":"oops"}`))
	if err == nil || !strings.Contains(err.Error(), "invalid contents") || rpcCode(t, err) != -32603 {
		t.Fatalf("err = %v", err)
	}
}

func TestExposedReadAcceptsAResultWithoutContents(t *testing.T) {
	got, err := exposedRead("srv", json.RawMessage(`{}`))
	if err != nil || !strings.Contains(string(got), `"resultType":"complete"`) {
		t.Fatalf("got %s, %v", got, err)
	}
}

func TestToolResultShapes(t *testing.T) {
	passedThrough := []string{`{"resultType":"input_required","x":1}`, `{"resultType":"task","taskId":"t"}`}
	for _, result := range passedThrough {
		got, err := toolResult(json.RawMessage(result))
		if err != nil || string(got) != result {
			t.Errorf("%s: got %s, %v", result, got, err)
		}
	}
	refused := []string{`{"resultType":"future"}`, `{"resultType":"complete"}`, `{}`, `{"other":1}`}
	for _, result := range refused {
		_, err := toolResult(json.RawMessage(result))
		if err == nil || !strings.Contains(err.Error(), "unsupported upstream result") || rpcCode(t, err) != -32603 {
			t.Errorf("%s: err = %v", result, err)
		}
	}
	for _, result := range []string{`{"isError":true}`, `{"structuredContent":{}}`, `{"resultType":"complete","content":[]}`} {
		if _, err := toolResult(json.RawMessage(result)); err != nil {
			t.Errorf("%s: %v", result, err)
		}
	}
}

func TestUpstreamErrorsKeepTheirCodeAndHideSecrets(t *testing.T) {
	log := &syncBuffer{}
	u := fake("one", nil).build(&upstream.Hub{}, store.NewMemory(), log)
	defer u.Shutdown()

	plain := upstreamError(u, errors.New("connection reset"))
	if rpcCode(t, plain) != -32603 || !strings.Contains(plain.Error(), "upstream request failed: connection reset") {
		t.Fatalf("got %v", plain)
	}

	own := upstreamError(u, &mcpwire.Error{Code: -32000, Message: "rate limited"})
	if rpcCode(t, own) != -32000 || !strings.Contains(own.Error(), "rate limited") {
		t.Fatalf("got %v", own)
	}
}
