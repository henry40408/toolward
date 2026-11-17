package config

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const sample = `{
  // JSONC comments and trailing commas are accepted
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "server-github"],
      "env": { "TOKEN": "${keychain:github}", "LOG": "info" },
      "disabled": false,
    },
    "internal": {
      "type": "http",
      "url": "https://mcp.example.com/mcp",
      "headers": { "Authorization": "Bearer ${keychain:internal}" }
    },
    "sentry": {
      "type": "http",
      "url": "https://mcp.sentry.dev/mcp",
      "oauth": { "scopes": ["org:read"], "clientId": "tw-client", "clientSecret": "${keychain:sentry-cs}" }
    }
  }
}`

func parseError(t *testing.T, text string) string {
	t.Helper()
	_, err := Parse(text)
	if err == nil {
		t.Fatalf("expected an error for %s", text)
	}
	return err.Error()
}

func mustParse(t *testing.T, text string) *Config {
	t.Helper()
	config, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func oneServer(server string) string {
	return fmt.Sprintf(`{"mcpServers": {"s": %s}}`, server)
}

func TestParsesTheSample(t *testing.T) {
	config := mustParse(t, sample)
	if len(config.Servers) != 3 {
		t.Fatalf("servers = %d", len(config.Servers))
	}
	if !slices.Equal(config.Names(), []string{"github", "internal", "sentry"}) {
		t.Fatalf("names = %v", config.Names())
	}
	github := config.Servers["github"]
	transport, err := github.Transport()
	if err != nil || transport.Stdio == nil || transport.Stdio.Command != "npx" {
		t.Fatalf("github transport = %+v, %v", transport, err)
	}
	if _, ok := github.Extra["disabled"]; !ok {
		t.Fatal("the unused field was dropped")
	}
	transport, err = config.Servers["sentry"].Transport()
	if err != nil || transport.HTTP == nil || transport.HTTP.OAuth == nil {
		t.Fatalf("sentry transport = %+v, %v", transport, err)
	}
}

func TestCollectsReferencesPerServer(t *testing.T) {
	refs := mustParse(t, sample).References()
	want := map[string][]string{
		"github":   {"github"},
		"internal": {"internal"},
		"sentry":   {"sentry-cs"},
	}
	for name, accounts := range want {
		if !slices.Equal(refs[name], accounts) {
			t.Errorf("%s: %v, want %v", name, refs[name], accounts)
		}
	}
}

func TestReferencesAreSortedAndUnique(t *testing.T) {
	config := mustParse(t, oneServer(`{"command":"x","env":{"B":"${keychain:b}","A":"${keychain:b}${keychain:a}"}}`))
	if got := config.References()["s"]; !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("got %v", got)
	}
}

func TestEmptyServersIsValid(t *testing.T) {
	if got := len(mustParse(t, "{}").Servers); got != 0 {
		t.Fatalf("servers = %d", got)
	}
}

func TestRejectsInconsistentOAuthSettings(t *testing.T) {
	for _, server := range []string{
		`{"url": "https://x/mcp", "oauth": {}, "headers": {"A": "b"}}`,
		`{"url": "https://x/mcp", "oauth": {"clientSecret": "${keychain:s}"}}`,
	} {
		if _, err := Parse(oneServer(server)); err == nil {
			t.Errorf("accepted %s", server)
		}
	}
}

func TestRejectsBadDocuments(t *testing.T) {
	tests := []struct{ text, want string }{
		{"", "config file is empty"},
		{"  \n\t", "config file is empty"},
		{"// only a comment", "config file is empty"},
		{"/* block */", "config file is empty"},
		{"null", "config file is empty"},
		{"{ nope", "invalid JSON"},
		{`{"mcpServers": []}`, "invalid config"},
		{`[]`, "invalid config"},
		{`{"mcpservers": {}, "mcpServers": {"s": null}}`, "invalid config"},
	}
	for _, tc := range tests {
		if got := parseError(t, tc.text); !strings.Contains(got, tc.want) {
			t.Errorf("%q: %q does not contain %q", tc.text, got, tc.want)
		}
	}
}

func TestFieldNamesAreCaseSensitive(t *testing.T) {
	config := mustParse(t, `{"MCPSERVERS": {"s": {"command": "x"}}}`)
	if len(config.Servers) != 0 {
		t.Fatal("a differently cased key was read")
	}
}

func TestRejectsBadNames(t *testing.T) {
	for _, name := range []string{"a__b", "_a", "a_", "a b", ""} {
		text := fmt.Sprintf(`{"mcpServers": {%q: {"command": "x"}}}`, name)
		if got := parseError(t, text); !strings.Contains(got, "name must be") {
			t.Errorf("%q: %s", name, got)
		}
	}
}

func TestRejectsLongNamesAndDashUnderscoreClashes(t *testing.T) {
	long := strings.Repeat("a", MaxNameLen+1)
	text := fmt.Sprintf(`{"mcpServers": {%q: {"command": "x"}}}`, long)
	want := `server "` + long + `": name must be at most 20 characters: it is part of every tool name`
	if got := parseError(t, text); got != want {
		t.Errorf("got %q", got)
	}
	ok := strings.Repeat("a", MaxNameLen)
	mustParse(t, fmt.Sprintf(`{"mcpServers": {%q: {"command": "x"}}}`, ok))

	clash := `{"mcpServers": {"a-b": {"command": "x"}, "a_b": {"command": "x"}}}`
	want = `server "a_b": name differs from "a-b" only by '-' versus '_'; some clients treat them as the same`
	if got := parseError(t, clash); got != want {
		t.Errorf("got %q", got)
	}
}

func TestRejectsBadTransports(t *testing.T) {
	tests := []struct{ server, want string }{
		{`{}`, "set either 'command' (stdio) or 'url' (http)"},
		{`{"command":"x","url":"http://h"}`, "set either 'command' or 'url', not both"},
		{`{"type":"sse","url":"http://h"}`, `unsupported type "sse": expected "stdio" or "http"`},
		{`{"type":"http","command":"x"}`, `type "http" does not match the fields given`},
		{`{"type":"stdio","url":"http://h"}`, `type "stdio" does not match the fields given`},
		{`{"command":"x","headers":{"a":"b"}}`, "'headers' and 'oauth' apply only to http servers"},
		{`{"command":"x","oauth":{}}`, "'headers' and 'oauth' apply only to http servers"},
		{`{"url":"http://h","env":{"a":"b"}}`, "'args' and 'env' apply only to stdio servers"},
		{`{"url":"http://h","oauth":{},"headers":{"a":"b"}}`, "'headers' cannot be combined with 'oauth'"},
		{`{"url":"http://h","oauth":{"clientSecret":"x"}}`, "oauth 'clientSecret' needs 'clientId'"},
	}
	for _, tc := range tests {
		want := `server "s": ` + tc.want
		if got := parseError(t, oneServer(tc.server)); got != want {
			t.Errorf("%s: got %q, want %q", tc.server, got, want)
		}
	}
}

func TestAcceptsExplicitTypes(t *testing.T) {
	mustParse(t, oneServer(`{"type":"stdio","command":"x"}`))
	mustParse(t, oneServer(`{"type":"http","url":"http://h"}`))
}

func TestRejectsReferencesInCommandAndUnusedFields(t *testing.T) {
	tests := []struct{ server, want string }{
		{`{"command":"${keychain:x}"}`, "'command' must not"},
		{`{"command":"x","args":["--token=${keychain:x}"]}`, "'args' must not"},
		{`{"url":"https://h/mcp?key=${keychain:x}"}`, "'url' must not"},
		{`{"command":"x","cwd":"${keychain:x}"}`, `not supported in field "cwd"`},
		{`{"command":"x","nested":{"a":[{"b":"${keychain:x}"}]}}`, `not supported in field "nested"`},
	}
	for _, tc := range tests {
		if got := parseError(t, oneServer(tc.server)); !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q does not contain %q", tc.server, got, tc.want)
		}
	}
}

func TestErrorsDoNotEchoConfigText(t *testing.T) {
	text := oneServer(`{"command":"x","env":{"A":"ghp_LEAK ${keychain:x"}}`)
	if got := parseError(t, text); strings.Contains(got, "ghp_LEAK") {
		t.Fatalf("leaked: %s", got)
	}
}

func TestRejectsBadReferencesAtLoadTime(t *testing.T) {
	text := oneServer(`{"command":"x","env":{"A":"${HOME}"}}`)
	want := `server "s": unsupported '${...}' reference: only '${keychain:<account>}' is supported`
	if got := parseError(t, text); got != want {
		t.Fatalf("got %q", got)
	}
}

func TestLoadReportsAMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil || !strings.Contains(err.Error(), "cannot read") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadReadsAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, sample)
	config, err := Load(path)
	if err != nil || len(config.Servers) != 3 {
		t.Fatalf("got %v, %v", config, err)
	}
}

func TestOAuthServers(t *testing.T) {
	config := mustParse(t, sample)
	if got := config.OAuthServers(); !slices.Equal(got, []string{"sentry"}) {
		t.Fatalf("got %v", got)
	}
	url, oauth, err := config.OAuthServer("sentry")
	if err != nil || url != "https://mcp.sentry.dev/mcp" || *oauth.ClientID != "tw-client" {
		t.Fatalf("got %q %+v %v", url, oauth, err)
	}
}

func TestOAuthServerErrors(t *testing.T) {
	config := mustParse(t, sample)
	tests := map[string]string{
		"nope":     `no server named "nope" in the config`,
		"github":   `server "github" has no "oauth" setting`,
		"internal": `server "internal" has no "oauth" setting`,
	}
	for name, want := range tests {
		if _, _, err := config.OAuthServer(name); err == nil || err.Error() != want {
			t.Errorf("%s: got %v, want %s", name, err, want)
		}
	}
}

func TestOAuthSettingsAreDecoded(t *testing.T) {
	config := mustParse(t, oneServer(`{"url":"http://h","oauth":{"scopes":["a"],"clientId":"id","callbackPort":8123}}`))
	oauth := config.Servers["s"].OAuth
	if !slices.Equal(oauth.Scopes, []string{"a"}) || *oauth.ClientID != "id" || *oauth.CallbackPort != 8123 {
		t.Fatalf("oauth = %+v", oauth)
	}
	if oauth.ClientSecret != nil {
		t.Fatal("clientSecret appeared from nowhere")
	}
	parseError(t, oneServer(`{"url":"http://h","oauth":{"callbackPort":70000}}`))
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	t.Setenv("HOME", "/home/u")
	if got, _ := DefaultPath(); got != "/xdg/toolward/config.json" {
		t.Errorf("with XDG_CONFIG_HOME: %q", got)
	}
	t.Setenv("XDG_CONFIG_HOME", "relative")
	if got, _ := DefaultPath(); got != "/home/u/.config/toolward/config.json" {
		t.Errorf("with a relative XDG_CONFIG_HOME: %q", got)
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	if got, _ := DefaultPath(); got != "/home/u/.config/toolward/config.json" {
		t.Errorf("without XDG_CONFIG_HOME: %q", got)
	}
}

func TestSyntaxErrorsDoNotEchoConfigText(t *testing.T) {
	for _, text := range []string{
		`{"env":{"A":ghp_abc123}}`,
		`{"env":{"A":ghp abc123}}`,
		`tghp_abc123`,
		"{\"a\":\nghp_abc123}",
	} {
		got := parseError(t, text)
		if strings.Contains(got, "ghp") || strings.Contains(got, "abc123") {
			t.Errorf("%q: error quotes the input: %q", text, got)
		}
		if !strings.Contains(got, "invalid JSON on line") {
			t.Errorf("%q: %q has no position", text, got)
		}
	}
}

func TestNullDocumentsWithWhitespaceAreEmpty(t *testing.T) {
	for _, text := range []string{"null\n", " null ", "// c\nnull"} {
		if got := parseError(t, text); !strings.Contains(got, "config file is empty") {
			t.Errorf("%q: %q", text, got)
		}
	}
}

func TestRejectsNullForListsAndMaps(t *testing.T) {
	for _, text := range []string{
		`{"mcpServers": null}`,
		oneServer(`{"command": "x", "args": null}`),
		oneServer(`{"command": "x", "env": null}`),
		oneServer(`{"url": "https://x/mcp", "headers": null}`),
	} {
		if got := parseError(t, text); !strings.Contains(got, "invalid config") {
			t.Errorf("%s: %q", text, got)
		}
	}
	mustParse(t, oneServer(`{"type": null, "command": "x"}`))
}
