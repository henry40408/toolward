package importer

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
)

const testSource = `{
  // comments are fine
  "mcpServers": {
    "gh": {"type": "http", "url": "https://x/mcp",
           "headers": {"Authorization": "Bearer ghp_SECRET1", "X-Team": "red"}},
    "db": {"command": "db", "args": ["--port", "5"],
           "env": {"DB_TOKEN": "tok-SECRET2", "MODE": "fast"}},
    "ref": {"command": "r", "env": {"API_KEY": "${API_KEY}"}},
    "arg": {"command": "a", "args": ["--password=hunter22"]},
    "url": {"url": "https://u:hunter23@h/mcp"},
    "bad": {"command": ["--token ghp_LEAKARGSTR"]},
    "old": {"type": "sse", "url": "https://y/sse"}
  }
}`

func mustPlan(t *testing.T, source string) *Plan {
	t.Helper()
	plan, err := NewPlan(source)
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	return plan
}

func accountsOf(plan *Plan) []string {
	var accounts []string
	for _, moved := range plan.Moves {
		accounts = append(accounts, moved.Account)
	}
	return accounts
}

func reportOf(t *testing.T, plan *Plan, applied bool) string {
	t.Helper()
	var out bytes.Buffer
	if err := Report(plan, applied, &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestPlanMovesWithoutExposingValues(t *testing.T) {
	plan := mustPlan(t, testSource)

	want := []Move{
		{Server: "db", Place: "env DB_TOKEN", Account: "db-db_token"},
		{Server: "gh", Place: "header Authorization", Account: "gh-authorization"},
	}
	if !slices.Equal(plan.Moves, want) {
		t.Errorf("moves = %v", plan.Moves)
	}
	config := plan.ConfigJSON()
	if strings.Contains(config, "SECRET") {
		t.Errorf("config holds a secret: %s", config)
	}
	for _, want := range []string{"Bearer ${keychain:gh-authorization}", "${keychain:db-db_token}", `"MODE":"fast"`} {
		if !strings.Contains(config, want) {
			t.Errorf("missing %q in %s", want, config)
		}
	}
	if len(plan.Skipped) != 5 {
		t.Errorf("skipped = %v", plan.Skipped)
	}
	skipped := strings.Join(plan.Skipped, "\n") + strings.Join(plan.Notes, "\n")
	for _, leak := range []string{"hunter22", "LEAK", "hunter2"} {
		if strings.Contains(skipped, leak) {
			t.Errorf("skipped and notes leak %q: %s", leak, skipped)
		}
	}
	out := reportOf(t, plan, false)
	if strings.Contains(out, "SECRET") || strings.Contains(out, "hunter22") {
		t.Errorf("report leaks a secret: %s", out)
	}
}

func TestPlanDoesNotPrintSecrets(t *testing.T) {
	plan := mustPlan(t, testSource)
	for _, text := range []string{plan.String()} {
		if strings.Contains(text, "SECRET") {
			t.Errorf("leak in %s", text)
		}
	}
}

func TestPlanKeepsAReferenceItDoesNotUnderstand(t *testing.T) {
	plan := mustPlan(t, `{"mcpServers": {"r": {"command": "r", "env": {"API_KEY": "${API_KEY}"}}}}`)
	if len(plan.Skipped) != 1 {
		t.Errorf("skipped = %v", plan.Skipped)
	}
	if len(plan.Moves) != 0 || len(plan.Notes) != 0 {
		t.Errorf("moves = %v, notes = %v", plan.Moves, plan.Notes)
	}
}

func TestPlanLeavesNoteForForeignReferenceInAServerThatLoads(t *testing.T) {
	source := `{"mcpServers": {"r": {"url": "https://x/mcp", "headers": {"X-Api-Key": "${keychain:ok}-${HOME}"}}}}`
	plan := mustPlan(t, source)
	if len(plan.Skipped) != 1 {
		t.Errorf("skipped = %v notes = %v", plan.Skipped, plan.Notes)
	}
}

func TestRejectsFilesWithoutServers(t *testing.T) {
	for _, source := range []string{"{}", "not json", "[]", "", "null"} {
		if _, err := NewPlan(source); err == nil {
			t.Errorf("NewPlan(%q) succeeded", source)
		}
	}
}

func TestDetectsMoreNamesAndValues(t *testing.T) {
	for _, name := range []string{"DB_PASS", "MYSQL_PWD", "GH_PAT", "SENTRY_DSN", "api-key"} {
		if !looksSecret(name) {
			t.Errorf("looksSecret(%q) = false", name)
		}
	}
	for _, name := range []string{"PATH", "MODE", "HOME", "PASSIVE"} {
		if looksSecret(name) {
			t.Errorf("looksSecret(%q) = true", name)
		}
	}
	if !hasSecretPrefix("ghp_abc") {
		t.Error("ghp_ is not a secret prefix")
	}
}

func TestAccountNamesAreValidAndUnique(t *testing.T) {
	for _, test := range []struct{ server, key, want string }{
		{"My Server", "API/KEY", "my-server-api-key"},
		{"oauth.x", "T", "imported-oauth.x-t"},
		{"oauth-client.x", "T", "imported-oauth-client.x-t"},
	} {
		if got := accountName(test.server, test.key); got != test.want {
			t.Errorf("accountName(%q, %q) = %q, want %q", test.server, test.key, got, test.want)
		}
	}
	planner := &planner{used: map[string]bool{}}
	if first, second := planner.unique("a"), planner.unique("a"); first != "a" || second != "a-2" {
		t.Errorf("unique = %q, %q", first, second)
	}
}

func TestSplitScheme(t *testing.T) {
	for _, test := range []struct{ value, scheme, secret string }{
		{"Bearer abc", "Bearer ", "abc"},
		{"bearer abc", "bearer ", "abc"},
		{"Basic abc", "Basic ", "abc"},
		{"Bearer ", "", "Bearer "},
		{"abc", "", "abc"},
	} {
		scheme, secret := splitScheme(test.value)
		if scheme != test.scheme || secret != test.secret {
			t.Errorf("splitScheme(%q) = %q, %q", test.value, scheme, secret)
		}
	}
}

func TestReportWithoutMovesSaysSo(t *testing.T) {
	out := reportOf(t, mustPlan(t, `{"mcpServers": {"a": {"command": "x"}}}`), true)
	if !strings.Contains(out, "no secret-looking env or header values found") || !strings.Contains(out, "Next:") {
		t.Errorf("report = %s", out)
	}
}

func TestPlanNeverFormatsSecrets(t *testing.T) {
	plan := mustPlan(t, testSource)

	for _, got := range []string{
		fmt.Sprintf("%v", plan), fmt.Sprintf("%+v", plan), fmt.Sprintf("%#v", plan),
		fmt.Sprintf("%v", *plan), fmt.Sprintf("%+v", *plan), fmt.Sprintf("%#v", *plan),
	} {
		if strings.Contains(got, "SECRET") {
			t.Errorf("formatted plan leaks a secret: %s", got)
		}
	}
}

func TestTempPathKeepsDotfilesApart(t *testing.T) {
	for path, want := range map[string]string{
		"/h/.toolward":     "/h/.toolward.json.tmp",
		"/h/config":        "/h/config.json.tmp",
		"/h/config.json":   "/h/config.json.tmp",
		"/h/a.b.json":      "/h/a.b.json.tmp",
		"/h/.toolward.cfg": "/h/.toolward.json.tmp",
	} {
		if got := tempPath(path); got != want {
			t.Errorf("tempPath(%s) = %s, want %s", path, got, want)
		}
	}
}
