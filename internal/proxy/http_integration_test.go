package proxy

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/store"
	"github.com/henry40408/toolward/internal/testing/httpfake"
	"github.com/henry40408/toolward/internal/upstream"
)

const longTool = "create_pull_request_review_comment_thread_reply"

// httpServer describes one upstream that talks to an httpfake.
type httpServer struct {
	name        string
	url         string
	headers     map[string]string
	listTimeout time.Duration
}

// startHTTP connects an agent to a proxy over the given HTTP upstreams.
func startHTTP(t *testing.T, secrets map[string]string, servers ...httpServer) *harness {
	t.Helper()
	hub := &upstream.Hub{}
	log := &syncBuffer{}
	var upstreams []*upstream.Upstream
	for _, server := range servers {
		upstreams = append(upstreams, upstream.New(upstream.Config{
			Name: server.name,
			Connector: &upstream.HTTPConnector{
				Spec:  upstream.HTTPSpec{URL: server.url, Headers: server.headers},
				Store: store.NewMemoryWith(secrets),
			},
			Hub:         hub,
			Log:         log,
			ListTimeout: server.listTimeout,
		}))
	}
	proxy := New(Options{Hub: hub, Upstreams: upstreams, Log: log})
	return connectAgent(t, proxy, log, mcpwire.Discover)
}

func plainServer(name, url string) httpServer {
	return httpServer{name: name, url: url}
}

func bearerServer(name, url string) httpServer {
	return httpServer{name: name, url: url, headers: map[string]string{"Authorization": "Bearer ${keychain:tok}"}}
}

var tokenSecret = map[string]string{"tok": "s3cr3t"}

// textOf returns the first text of a tool result.
func textOf(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || len(result.Content) == 0 {
		t.Fatalf("result = %s, %v", raw, err)
	}
	return result.Content[0].Text
}

func (h *harness) resourceURIs() []string {
	h.t.Helper()
	var result struct {
		Resources []struct {
			URI string `json:"uri"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(h.mustRequest("resources/list", `{}`), &result); err != nil {
		h.t.Fatal(err)
	}
	var uris []string
	for _, resource := range result.Resources {
		uris = append(uris, resource.URI)
	}
	return uris
}

func (h *harness) promptNames() []string {
	h.t.Helper()
	var result struct {
		Prompts []struct {
			Name string `json:"name"`
		} `json:"prompts"`
	}
	if err := json.Unmarshal(h.mustRequest("prompts/list", `{}`), &result); err != nil {
		h.t.Fatal(err)
	}
	var names []string
	for _, prompt := range result.Prompts {
		names = append(names, prompt.Name)
	}
	return names
}

func TestHTTPToolsArePrefixedForwardedAndGetTheSecretHeader(t *testing.T) {
	fake := httpfake.New(t, "echo", "whoami")
	h := startHTTP(t, tokenSecret, bearerServer("web", fake.URL))

	if got := h.toolNames(); !slices.Equal(got, []string{"web__echo", "web__whoami"}) {
		t.Fatalf("tools = %v", got)
	}
	raw, err := h.callTool("web__whoami", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	// The upstream echoes the header it received; the agent must not see it.
	if got := textOf(t, raw); got != "Bearer [REDACTED]" {
		t.Errorf("text = %q", got)
	}
	if strings.Contains(string(raw), "s3cr3t") {
		t.Errorf("the result carries the secret: %s", raw)
	}
}

func TestHTTPSecretsAreMaskedInResourcesAndPrompts(t *testing.T) {
	fake := httpfake.New(t)
	h := startHTTP(t, tokenSecret, httpServer{name: "web", url: fake.URL, headers: map[string]string{"Authorization": "${keychain:tok}"}})

	uris := h.resourceURIs()
	read := string(h.mustRequest("resources/read", `{"uri":"`+uris[0]+`"}`))
	if !strings.Contains(read, "hello[REDACTED]") || strings.Contains(read, "s3cr3t") {
		t.Errorf("read = %s", read)
	}
	prompt := string(h.mustRequest("prompts/get", `{"name":"web__greet"}`))
	if !strings.Contains(prompt, "greet[REDACTED]") || strings.Contains(prompt, "s3cr3t") {
		t.Errorf("prompt = %s", prompt)
	}
}

func TestHTTPLongNamesAreShortenedAndBothNamesCanBeCalled(t *testing.T) {
	fake := httpfake.New(t, longTool, "short")
	h := startHTTP(t, nil, plainServer("gh", fake.URL))

	names := h.toolNames()
	var shortened string
	for _, name := range names {
		if strings.HasPrefix(name, "gh__create_pull_request") {
			shortened = name
		}
	}
	if shortened == "" || len(shortened) > 49 {
		t.Fatalf("shortened name %q in %v", shortened, names)
	}
	if !slices.Contains(names, "gh__short") {
		t.Errorf("names = %v", names)
	}
	for _, name := range []string{shortened, "gh__" + longTool} {
		raw, err := h.callTool(name, `{}`)
		if err != nil {
			t.Fatal(err)
		}
		if got := textOf(t, raw); got != "called "+longTool {
			t.Errorf("%s: text = %q", name, got)
		}
	}
}

func TestHTTPAnUnknownToolTriggersARelistBeforeFailing(t *testing.T) {
	fake := httpfake.New(t, "old")
	h := startHTTP(t, nil, plainServer("web", fake.URL))

	h.toolNames()
	fake.SetTools("old", "fresh")
	raw, err := h.callTool("web__fresh", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := textOf(t, raw); got != "called fresh" {
		t.Errorf("text = %q", got)
	}
	_, err = h.callTool("web__nope", `{}`)
	if err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("err = %v", err)
	}
}

func TestHTTPResourcesRoundTripThroughRewrittenURIs(t *testing.T) {
	fake := httpfake.New(t)
	h := startHTTP(t, nil, plainServer("web", fake.URL))

	uris := h.resourceURIs()
	if len(uris) != 1 || !strings.HasPrefix(uris[0], "toolward://web/") {
		t.Fatalf("uris = %v", uris)
	}
	var read struct {
		Contents []struct {
			URI  string `json:"uri"`
			Text string `json:"text"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(h.mustRequest("resources/read", `{"uri":"`+uris[0]+`"}`), &read); err != nil {
		t.Fatal(err)
	}
	if len(read.Contents) != 1 || read.Contents[0].Text != "hello" || read.Contents[0].URI != uris[0] {
		t.Errorf("read = %+v", read)
	}
	_, err := h.request("resources/read", `{"uri":"file:///etc/passwd"}`)
	if err == nil || !strings.Contains(err.Error(), "unknown resource") {
		t.Errorf("err = %v", err)
	}
}

func TestHTTPPromptsGetTheServerPrefix(t *testing.T) {
	fake := httpfake.New(t)
	h := startHTTP(t, nil, plainServer("web", fake.URL))

	if got := h.promptNames(); !slices.Equal(got, []string{"web__greet"}) {
		t.Fatalf("prompts = %v", got)
	}
	if got := string(h.mustRequest("prompts/get", `{"name":"web__greet"}`)); !strings.Contains(got, "prompt greet") {
		t.Errorf("prompt = %s", got)
	}
}

func TestHTTPFailingUpstreamIsSkippedAndNeverLeaksTheSecret(t *testing.T) {
	good := httpfake.New(t, "echo")
	bad := httpfake.New(t, "hidden")
	bad.FailWith(500)
	h := startHTTP(t, tokenSecret, plainServer("good", good.URL), bearerServer("bad", bad.URL))

	if got := h.toolNames(); !slices.Equal(got, []string{"good__echo"}) {
		t.Fatalf("tools = %v", got)
	}
	_, err := h.callTool("bad__hidden", `{}`)
	if err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("err = %v", err)
	}
	// The server did get the header; only our output is checked for leaks.
	if !slices.Contains(bad.Authorizations(), "Bearer s3cr3t") {
		t.Errorf("authorizations = %v", bad.Authorizations())
	}
}

func TestHTTPMissingSecretMakesTheUpstreamUnavailable(t *testing.T) {
	fake := httpfake.New(t, "echo")
	h := startHTTP(t, nil, httpServer{name: "web", url: fake.URL, headers: map[string]string{"Authorization": "Bearer ${keychain:absent}"}})

	if names := h.toolNames(); len(names) != 0 {
		t.Errorf("tools = %v", names)
	}
	_, err := h.callTool("web__echo", `{}`)
	if err == nil || !strings.Contains(err.Error(), "absent") {
		t.Errorf("err = %v", err)
	}
	// Nothing reached the server: the request was never built.
	if requests := fake.Requests(); len(requests) != 0 {
		t.Errorf("requests = %+v", requests)
	}
}

func TestHTTPErrorsAfterTheHandshakeAreRedacted(t *testing.T) {
	fake := httpfake.New(t, "echo")
	h := startHTTP(t, tokenSecret, bearerServer("web", fake.URL))

	if got := h.toolNames(); len(got) != 1 {
		t.Fatalf("tools = %v", got)
	}
	fake.FailWith(500)
	_, err := h.callTool("web__echo", `{}`)
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") || strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("err = %v", err)
	}
}

func TestHTTPAToolListedTwiceIsExposedOnce(t *testing.T) {
	fake := httpfake.New(t, "dup", "dup", "other")
	h := startHTTP(t, nil, plainServer("web", fake.URL))

	if got := h.toolNames(); !slices.Equal(got, []string{"web__dup", "web__other"}) {
		t.Errorf("tools = %v", got)
	}
}

func TestHTTPTheHandshakeOffersAVersionThatHasInitialize(t *testing.T) {
	fake := httpfake.New(t)
	h := startHTTP(t, nil, plainServer("web", fake.URL))

	h.toolNames()
	if got := fake.Versions(); !slices.Equal(got, []string{"2025-11-25"}) {
		t.Errorf("versions = %v", got)
	}
}

func TestHTTPALegacyServerThatFailsTheProbeWithA5xxIsStillReached(t *testing.T) {
	fake := httpfake.New(t, "echo")
	fake.DiscoverStatus(500)
	h := startHTTP(t, nil, plainServer("web", fake.URL))

	if got := h.toolNames(); len(got) != 1 {
		t.Errorf("tools = %v", got)
	}
	if got := fake.Versions(); !slices.Equal(got, []string{"2025-11-25"}) {
		t.Errorf("versions = %v", got)
	}
}

// startWithSilentUpstream is a fresh harness with one silent and one working
// upstream, so each listing meets the silent one for the first time.
func startWithSilentUpstream(t *testing.T) *harness {
	t.Helper()
	silent := httpfake.NewSilent(t)
	fast := httpfake.New(t, "ping")
	hung := plainServer("hung", silent.URL)
	hung.listTimeout = 500 * time.Millisecond
	return startHTTP(t, nil, hung, plainServer("fast", fast.URL))
}

func TestHTTPASilentUpstreamDoesNotHoldUpAnyListing(t *testing.T) {
	limit := 10 * time.Second

	h := startWithSilentUpstream(t)
	started := time.Now()
	names := h.toolNames()
	assertQuick(t, started, limit)
	if !slices.Equal(names, []string{"fast__ping"}) {
		t.Errorf("tools = %v", names)
	}

	h = startWithSilentUpstream(t)
	started = time.Now()
	uris := h.resourceURIs()
	assertQuick(t, started, limit)
	if len(uris) != 1 || !strings.HasPrefix(uris[0], "toolward://fast/") {
		t.Errorf("resources = %v", uris)
	}

	h = startWithSilentUpstream(t)
	started = time.Now()
	prompts := h.promptNames()
	assertQuick(t, started, limit)
	if !slices.Equal(prompts, []string{"fast__greet"}) {
		t.Errorf("prompts = %v", prompts)
	}
}

func assertQuick(t *testing.T, started time.Time, limit time.Duration) {
	t.Helper()
	if elapsed := time.Since(started); elapsed >= limit {
		t.Errorf("the listing took %v", elapsed)
	}
}
