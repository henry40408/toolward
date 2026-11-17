package check

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/henry40408/toolward/internal/config"
	"github.com/henry40408/toolward/internal/store"
)

const testConfig = `{"mcpServers": {
	"a": {"command": "x", "env": {"T": "${keychain:present}"}},
	"b": {"command": "y", "env": {"T": "${keychain:absent}"}},
	"c": {"command": "z"}
}}`

func parse(t *testing.T, text string) *config.Config {
	t.Helper()
	cfg, err := config.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func textOf(t *testing.T, reports []*ServerReport, options TextOptions) string {
	t.Helper()
	var out bytes.Buffer
	if err := RenderText(&out, reports, options); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func jsonOf(t *testing.T, reports []*ServerReport) (string, map[string]any) {
	t.Helper()
	var out bytes.Buffer
	if err := RenderJSON(&out, reports); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(out.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	return out.String(), document
}

func secretReports(t *testing.T) []*ServerReport {
	t.Helper()
	secrets := store.NewMemoryWith(map[string]string{"present": "TOPSECRET"})
	return CheckSecrets(parse(t, testConfig), secrets)
}

func TestCapabilityNamesIncludeExtensionsAndSkipUnsetOnes(t *testing.T) {
	capabilities := json.RawMessage(`{"tools":{},"prompts":{},"logging":null,"extensions":{"io.modelcontextprotocol/tasks":{}}}`)
	want := []string{"io.modelcontextprotocol/tasks", "prompts", "tools"}
	if got := capabilityNames(capabilities); !reflect.DeepEqual(got, want) {
		t.Errorf("names = %v, want %v", got, want)
	}
	if got := capabilityNames(json.RawMessage(`{}`)); len(got) != 0 {
		t.Errorf("names = %v", got)
	}
	if got := capabilityNames(nil); len(got) != 0 {
		t.Errorf("names = %v", got)
	}
}

func TestSecretsAreReportedWithoutLeakingValues(t *testing.T) {
	reports := secretReports(t)
	text := textOf(t, reports, TextOptions{})

	if AllOK(reports) {
		t.Error("AllOK = true")
	}
	for _, want := range []string{"✓ present", "✗ absent missing", "no secret references"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	if strings.Contains(text, "TOPSECRET") {
		t.Errorf("the text leaks a secret: %s", text)
	}
}

func TestAProblemComesWithItsFix(t *testing.T) {
	text := textOf(t, secretReports(t), TextOptions{})
	if !strings.Contains(text, "fix: toolward secret set absent") {
		t.Errorf("text = %s", text)
	}
}

func TestSummaryCountsServersWithProblems(t *testing.T) {
	text := textOf(t, secretReports(t), TextOptions{})
	if !strings.HasSuffix(text, "3 servers, 1 with problem (run with --tools to also connect)\n") {
		t.Errorf("text = %s", text)
	}
	text = textOf(t, secretReports(t), TextOptions{ToolsChecked: true})
	if !strings.HasSuffix(text, "3 servers, 1 with problem\n") {
		t.Errorf("text = %s", text)
	}
}

func TestSummaryOfACleanConfig(t *testing.T) {
	reports := CheckSecrets(parse(t, `{"mcpServers": {}}`), store.NewMemory())
	if got := summary(reports, true); got != "0 servers, all ok" {
		t.Errorf("summary = %q", got)
	}
}

func TestColorMarksTheStatusAndLeavesTheTextReadable(t *testing.T) {
	secrets := store.NewMemoryWith(map[string]string{"present": "x"})
	reports := CheckSecrets(parse(t, testConfig), secrets)

	text := textOf(t, reports, TextOptions{ToolsChecked: true, Color: true})
	for _, want := range []string{"\x1b[32m✓\x1b[0m present", "\x1b[31m✗\x1b[0m absent missing", "\x1b[2mfix: toolward secret set absent\x1b[0m"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	if plain := textOf(t, reports, TextOptions{ToolsChecked: true}); strings.Contains(plain, "\x1b") {
		t.Errorf("plain text has escapes: %s", plain)
	}
}

func TestColorNeedsATerminalAndNoNoColor(t *testing.T) {
	tests := []struct {
		terminal bool
		noColor  string
		want     bool
	}{
		{true, "", true},
		{true, "1", false},
		{false, "", false},
	}
	for _, test := range tests {
		if got := WantsColor(test.terminal, test.noColor); got != test.want {
			t.Errorf("WantsColor(%v, %q) = %v", test.terminal, test.noColor, got)
		}
	}
}

func TestJSONHoldsTheFactsAndNoSecretValue(t *testing.T) {
	text, document := jsonOf(t, secretReports(t))

	if strings.Contains(text, "TOPSECRET") || strings.Contains(text, "\x1b") {
		t.Errorf("text = %s", text)
	}
	if !strings.HasSuffix(text, "}\n") || strings.Count(text, "\n") != 1 {
		t.Errorf("text is not one line: %q", text)
	}
	if document["ok"] != false {
		t.Errorf("ok = %v", document["ok"])
	}
	servers := document["servers"].([]any)
	if len(servers) != 3 {
		t.Fatalf("servers = %v", servers)
	}
	first := servers[0].(map[string]any)
	if first["name"] != "a" || first["ok"] != true {
		t.Errorf("first = %v", first)
	}
	if got := first["secrets"].([]any)[0]; !reflect.DeepEqual(got, map[string]any{"account": "present", "status": "ok"}) {
		t.Errorf("secret = %v", got)
	}
	if got := servers[1].(map[string]any); got["ok"] != false || got["secrets"].([]any)[0].(map[string]any)["status"] != "missing" {
		t.Errorf("second = %v", got)
	}
	if got := servers[2].(map[string]any)["secrets"]; !reflect.DeepEqual(got, []any{}) {
		t.Errorf("third secrets = %v", got)
	}
	if first["oauth"] != nil || first["upstream"] != nil {
		t.Errorf("oauth = %v, upstream = %v", first["oauth"], first["upstream"])
	}
}

// fixedStore answers every Get the same way.
type fixedStore struct {
	secret string
	found  bool
	err    error
}

func (s fixedStore) Get(string) (string, bool, error) { return s.secret, s.found, s.err }
func (s fixedStore) Set(string, string) error         { panic("check never writes") }
func (s fixedStore) Delete(string) (bool, error)      { panic("check never writes") }

const oauthConfig = `{"mcpServers": {
	"s": {"url": "https://x/mcp", "oauth": {}},
	"t": {"command": "x", "env": {"T": "${keychain:token}"}}
}}`

func oauthReports(t *testing.T, secrets store.Store) []*ServerReport {
	t.Helper()
	return CheckSecrets(parse(t, oauthConfig), secrets)
}

func serverJSON(document map[string]any, index int) map[string]any {
	return document["servers"].([]any)[index].(map[string]any)
}

func TestOAuthLoggedInIsOK(t *testing.T) {
	reports := oauthReports(t, fixedStore{secret: "x", found: true})
	text := textOf(t, reports, TextOptions{ToolsChecked: true})
	if !strings.Contains(text, "✓ oauth logged in") || !AllOK(reports) {
		t.Errorf("text = %s", text)
	}
	_, document := jsonOf(t, reports)
	if got := serverJSON(document, 0)["oauth"].(map[string]any)["status"]; got != "logged_in" {
		t.Errorf("status = %v", got)
	}
}

func TestOAuthNotLoggedInNamesTheLoginCommand(t *testing.T) {
	reports := oauthReports(t, fixedStore{})
	text := textOf(t, reports, TextOptions{ToolsChecked: true})
	for _, want := range []string{"✗ oauth not logged in", "fix: toolward auth login s"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	_, document := jsonOf(t, reports)
	oauth := serverJSON(document, 0)["oauth"].(map[string]any)
	if _, hasReason := oauth["reason"]; oauth["status"] != "not_logged_in" || hasReason {
		t.Errorf("oauth = %v", oauth)
	}
}

func TestStoreFailuresAreReportedForOAuthAndSecrets(t *testing.T) {
	reports := oauthReports(t, fixedStore{err: &store.BackendError{Message: "locked"}})
	text := textOf(t, reports, TextOptions{ToolsChecked: true})

	if AllOK(reports) {
		t.Error("AllOK = true")
	}
	for _, want := range []string{"✗ oauth error: credential store failure: locked", "✗ token error: credential store failure: locked"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	_, document := jsonOf(t, reports)
	if got := serverJSON(document, 0)["oauth"].(map[string]any)["status"]; got != "error" {
		t.Errorf("status = %v", got)
	}
	secret := serverJSON(document, 1)["secrets"].([]any)[0].(map[string]any)
	if secret["reason"] != "credential store failure: locked" {
		t.Errorf("secret = %v", secret)
	}
}

func TestAnOtherStoreErrorIsReportedToo(t *testing.T) {
	reports := oauthReports(t, fixedStore{err: errors.New("boom")})
	if text := textOf(t, reports, TextOptions{}); !strings.Contains(text, "✗ token error: boom") {
		t.Errorf("text = %s", text)
	}
}

func upstreamReport(upstream *UpstreamReport) []*ServerReport {
	return []*ServerReport{{Name: "s", Upstream: upstream}}
}

func ptr(text string) *string { return &text }

func TestAConnectedUpstreamShowsWhatItAnnounced(t *testing.T) {
	reports := upstreamReport(&UpstreamReport{
		Protocol:     ptr("2025-06-18"),
		Server:       ptr("srv 1.0"),
		Capabilities: []string{"prompts", "tools"},
		Tools: []ToolReport{
			{Name: "s__ping", Original: "ping"},
			{Name: "s__short_x1", Original: "a_very_long_name"},
		},
	})

	text := textOf(t, reports, TextOptions{ToolsChecked: true})
	for _, want := range []string{
		"✓ protocol 2025-06-18 · srv 1.0 · prompts, tools",
		"✓ 2 tools",
		"      s__ping\n",
		`s__short_x1  (renamed from "a_very_long_name")`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	_, document := jsonOf(t, reports)
	upstream := serverJSON(document, 0)["upstream"].(map[string]any)
	if upstream["status"] != "ok" || !reflect.DeepEqual(upstream["capabilities"], []any{"prompts", "tools"}) {
		t.Errorf("upstream = %v", upstream)
	}
	if got := upstream["tools"].([]any)[1].(map[string]any)["original"]; got != "a_very_long_name" {
		t.Errorf("original = %v", got)
	}
}

func TestAnUpstreamWithoutPeerInfoHasNoAnnouncement(t *testing.T) {
	reports := upstreamReport(&UpstreamReport{Tools: []ToolReport{{Name: "s__ping", Original: "ping"}}})

	text := textOf(t, reports, TextOptions{ToolsChecked: true})
	if strings.Contains(text, "protocol") || !strings.Contains(text, "✓ 1 tool\n") {
		t.Errorf("text = %s", text)
	}
	_, document := jsonOf(t, reports)
	upstream := serverJSON(document, 0)["upstream"].(map[string]any)
	if upstream["protocol"] != nil || upstream["server"] != nil {
		t.Errorf("upstream = %v", upstream)
	}
}

func TestAnAnnouncementWithoutServerOrCapabilities(t *testing.T) {
	got := announcement(&UpstreamReport{Protocol: ptr("2025-06-18")})
	if got != "protocol 2025-06-18 · (none)" {
		t.Errorf("announcement = %q", got)
	}
}

func TestAFailedUpstreamIsAProblemInBothFormats(t *testing.T) {
	reports := upstreamReport(&UpstreamReport{Failed: true, Reason: "boom"})

	if AllOK(reports) {
		t.Error("AllOK = true")
	}
	if text := textOf(t, reports, TextOptions{ToolsChecked: true}); !strings.Contains(text, "✗ tools unavailable: boom") {
		t.Errorf("text = %s", text)
	}
	_, document := jsonOf(t, reports)
	if got := serverJSON(document, 0)["upstream"]; !reflect.DeepEqual(got, map[string]any{"status": "error", "reason": "boom"}) {
		t.Errorf("upstream = %v", got)
	}
}

func TestAReportForAnUnknownServerIsAddedOnce(t *testing.T) {
	reports, report := reportFor(nil, "late")
	report.Upstream = &UpstreamReport{Failed: true, Reason: "x"}
	reports, _ = reportFor(reports, "late")
	if len(reports) != 1 {
		t.Errorf("reports = %d", len(reports))
	}
}

func TestJSONIsNotEscapedForHTML(t *testing.T) {
	reports := upstreamReport(&UpstreamReport{Failed: true, Reason: "a <b> & c"})
	text, _ := jsonOf(t, reports)
	if !strings.Contains(text, "a <b> & c") {
		t.Errorf("text = %s", text)
	}
}
