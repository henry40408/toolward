package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/henry40408/toolward/internal/store"
)

// session runs toolward in this process, with an in-memory credential store.
type session struct {
	t       *testing.T
	secrets *store.Memory
	stdin   string
	env     map[string]string
	// openStore replaces the in-memory store when a test needs it to fail.
	openStore func() (store.Store, error)
}

func newSession(t *testing.T) *session {
	return &session{t: t, secrets: store.NewMemory(), env: map[string]string{}}
}

func (s *session) newStore() (store.Store, error) {
	if s.openStore != nil {
		return s.openStore()
	}
	return s.secrets, nil
}

func (s *session) run(args ...string) (stdout, stderr string, code int) {
	s.t.Helper()
	input := filepath.Join(s.t.TempDir(), "stdin")
	if err := os.WriteFile(input, []byte(s.stdin), 0o600); err != nil {
		s.t.Fatal(err)
	}
	stdin, err := os.Open(input)
	if err != nil {
		s.t.Fatal(err)
	}
	defer stdin.Close()
	var out, errw bytes.Buffer
	code = run(process{
		args: args,
		lookupEnv: func(name string) (string, bool) {
			value, found := s.env[name]
			return value, found
		},
		stdin:    stdin,
		stdout:   &out,
		stderr:   &errw,
		newStore: s.newStore,
	})
	return out.String(), errw.String(), code
}

func TestSecretSetReadsStdinAndStripsOneNewline(t *testing.T) {
	s := newSession(t)
	s.stdin = "line1\nline2\r\n\n"
	stdout, stderr, code := s.run("secret", "set", "gh")
	if code != 0 || stderr != "" || stdout != "stored secret for \"gh\"\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if got, _, _ := s.secrets.Get("gh"); got != "line1\nline2\r\n" {
		t.Fatalf("stored %q", got)
	}
}

func TestSecretSetStripsACarriageReturnAfterTheNewline(t *testing.T) {
	s := newSession(t)
	s.stdin = "token\r\n"
	s.run("secret", "set", "gh")
	if got, _, _ := s.secrets.Get("gh"); got != "token" {
		t.Fatalf("stored %q", got)
	}
}

func TestSecretSetRefusesAnEmptySecretAndABadAccount(t *testing.T) {
	s := newSession(t)
	if _, stderr, code := s.run("secret", "set", "gh"); code != 1 || stderr != "error: refusing to store an empty secret\n" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	s.stdin = "x"
	if _, stderr, code := s.run("secret", "set", "a/b"); code != 1 || !strings.HasPrefix(stderr, "error: ") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if _, found, _ := s.secrets.Get("a/b"); found {
		t.Fatal("a rejected account must store nothing")
	}
}

func TestSecretDeleteSaysWhatHappened(t *testing.T) {
	s := newSession(t)
	_ = s.secrets.Set("gh", "tok")
	if stdout, _, code := s.run("secret", "delete", "gh"); code != 0 || stdout != "deleted secret for \"gh\"\n" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	if stdout, _, code := s.run("secret", "delete", "gh"); code != 0 || stdout != "no secret stored for \"gh\"\n" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
}

func TestAuthLogoutWithoutALogin(t *testing.T) {
	s := newSession(t)
	if stdout, _, code := s.run("auth", "logout", "sentry"); code != 0 || stdout != "no login stored for \"sentry\"\n" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	_ = s.secrets.Set("oauth.sentry", `{}`)
	if stdout, _, code := s.run("auth", "logout", "sentry"); code != 0 || stdout != "logged out of \"sentry\"\n" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
}

func TestAuthLoginNeedsAnOAuthServer(t *testing.T) {
	s := newSession(t)
	config := writeConfig(t, `{"mcpServers":{"plain":{"command":"x"}}}`)
	_, stderr, code := s.run("auth", "login", "plain", "--config", config)
	if code != 1 || !strings.Contains(stderr, `server "plain" has no "oauth" setting`) {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

const checkConfig = `{"mcpServers":{"gh":{"command":"x","env":{"T":"${keychain:gh-token}"}}}}`

func TestCheckExitsWithOneWhenASecretIsMissing(t *testing.T) {
	s := newSession(t)
	config := writeConfig(t, checkConfig)
	stdout, stderr, code := s.run("check", "--config", config)
	if code != 1 || stderr != "" || !strings.Contains(stdout, "toolward secret set gh-token") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	_ = s.secrets.Set("gh-token", "v")
	if _, _, code := s.run("check", "--config", config); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

func TestCheckJSONIsOneLineAndNeverColored(t *testing.T) {
	s := newSession(t)
	_ = s.secrets.Set("gh-token", "v")
	config := writeConfig(t, checkConfig)
	stdout, _, code := s.run("--config", config, "check", "--format", "json")
	if code != 0 || strings.Count(stdout, "\n") != 1 || strings.Contains(stdout, "\x1b") {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
}

func TestCheckColorsOnlyOnATerminalWithoutNoColor(t *testing.T) {
	config := writeConfig(t, `{"mcpServers":{"plain":{"command":"x"}}}`)
	for _, noColor := range []string{"", "1"} {
		s := newSession(t)
		s.env["NO_COLOR"] = noColor
		out := colorOutput(t, s, config)
		if got := strings.Contains(out, "\x1b[32m"); got != (noColor == "") {
			t.Errorf("NO_COLOR=%q: colored %v in %q", noColor, got, out)
		}
	}
}

// colorOutput runs check as if stdout were a terminal.
func colorOutput(t *testing.T, s *session, config string) string {
	t.Helper()
	var out bytes.Buffer
	run(process{
		args:             []string{"check", "--config", config},
		lookupEnv:        func(name string) (string, bool) { value, found := s.env[name]; return value, found },
		stdin:            os.Stdin,
		stdout:           &out,
		stderr:           &bytes.Buffer{},
		stdoutIsTerminal: true,
		newStore:         func() (store.Store, error) { return s.secrets, nil },
	})
	return out.String()
}

func TestTheConfigFlagWorksBeforeAndAfterTheCommandAndTheLaterOneWins(t *testing.T) {
	s := newSession(t)
	good := writeConfig(t, `{"mcpServers":{"plain":{"command":"x"}}}`)
	missing := filepath.Join(t.TempDir(), "nope.json")
	for _, args := range [][]string{
		{"--config", good, "check"},
		{"check", "--config", good},
		{"--config", missing, "check", "--config", good},
	} {
		if _, stderr, code := s.run(args...); code != 0 {
			t.Errorf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
	if _, _, code := s.run("--config", good, "check", "--config", missing); code != 1 {
		t.Fatalf("the flag after the command must win, exit %d", code)
	}
}

func TestTheDefaultConfigFollowsXDGConfigHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := os.MkdirAll(filepath.Join(dir, "toolward"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "toolward", "config.json"), []byte(`{"mcpServers":{"plain":{"command":"x"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if stdout, _, code := newSession(t).run("check"); code != 0 || !strings.Contains(stdout, "plain") {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
}

const importSource = `{"mcpServers":{"db":{"command":"db","env":{"DB_TOKEN":"tok-SECRET2"}}}}`

func TestImportShowsThePlanAndChangesNothingWithoutApply(t *testing.T) {
	s := newSession(t)
	source := writeConfig(t, importSource)
	stdout, _, code := s.run("import", source)
	if code != 0 || !strings.Contains(stdout, "would move db: ") || strings.Contains(stdout, "tok-SECRET2") {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
}

func TestImportApplyStoresTheSecretAndWritesTheConfig(t *testing.T) {
	s := newSession(t)
	source := writeConfig(t, importSource)
	target := filepath.Join(t.TempDir(), "config.json")
	stdout, stderr, code := s.run("import", source, "--apply", "--config", target)
	if code != 0 || !strings.Contains(stdout, "moved db: ") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	written, err := os.ReadFile(target)
	if err != nil || strings.Contains(string(written), "tok-SECRET2") || !strings.Contains(string(written), "${keychain:") {
		t.Fatalf("config %q, err %v", written, err)
	}
}

func TestImportOfAMissingFileSaysSo(t *testing.T) {
	_, stderr, code := newSession(t).run("import", filepath.Join(t.TempDir(), "nope.json"))
	if code != 1 || !strings.HasPrefix(stderr, "error: cannot read ") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestACommandHelpIsPrintedToStdout(t *testing.T) {
	stdout, stderr, code := newSession(t).run("check", "--help")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "Usage: toolward check") || !strings.Contains(stdout, "--tools") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestFlagsMayFollowTheArguments(t *testing.T) {
	s := newSession(t)
	source := writeConfig(t, importSource)
	if _, _, code := s.run("import", "--apply=false", source); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if _, stderr, code := s.run("import", source, "--bogus"); code != 2 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}
