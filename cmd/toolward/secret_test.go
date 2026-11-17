package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/henry40408/toolward/internal/store"
)

// failingStore fails every operation, as a locked Keychain would.
type failingStore struct{ err error }

func (f failingStore) Get(string) (string, bool, error) { return "", false, f.err }
func (f failingStore) Set(string, string) error         { return f.err }
func (f failingStore) Delete(string) (bool, error)      { return false, f.err }

func failWith(message string) func() (store.Store, error) {
	return func() (store.Store, error) { return failingStore{err: errors.New(message)}, nil }
}

func cannotOpen(message string) func() (store.Store, error) {
	return func() (store.Store, error) { return nil, errors.New(message) }
}

func TestSecretSetStopsWhenTheStoreCannotBeOpened(t *testing.T) {
	s := newSession(t)
	s.stdin = "token"
	s.openStore = cannotOpen("keychain unavailable")
	_, stderr, code := s.run("secret", "set", "gh")
	if code != 1 || stderr != "error: keychain unavailable\n" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestSecretSetReportsAStoreWriteFailureWithoutPrintingSuccess(t *testing.T) {
	s := newSession(t)
	s.stdin = "token"
	s.openStore = failWith("write denied")
	stdout, stderr, code := s.run("secret", "set", "gh")
	if code != 1 || stdout != "" || stderr != "error: write denied\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestSecretSetRejectsAReservedAccount(t *testing.T) {
	s := newSession(t)
	s.stdin = "token"
	_, stderr, code := s.run("secret", "set", "oauth.gh")
	if code != 1 || !strings.HasPrefix(stderr, "error: ") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if _, found, _ := s.secrets.Get("oauth.gh"); found {
		t.Fatal("a reserved account must store nothing")
	}
}

func TestSecretSetReportsAnUnreadableStdin(t *testing.T) {
	s := newSession(t)
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	stdin.Close() // reading a closed file fails
	var out, errw bytes.Buffer
	code := run(process{
		args:     []string{"secret", "set", "gh"},
		stdin:    stdin,
		stdout:   &out,
		stderr:   &errw,
		newStore: s.newStore,
	})
	if code != 1 || errw.String() != "error: cannot read the secret from stdin\n" {
		t.Fatalf("exit %d, stderr %q", code, errw.String())
	}
	if _, found, _ := s.secrets.Get("gh"); found {
		t.Fatal("nothing may be stored")
	}
}

func TestSecretSetKeepsAnInteriorBlankLine(t *testing.T) {
	s := newSession(t)
	s.stdin = "a\n\nb"
	s.run("secret", "set", "gh")
	if got, _, _ := s.secrets.Get("gh"); got != "a\n\nb" {
		t.Fatalf("stored %q", got)
	}
}

func TestSecretDeleteReportsStoreFailures(t *testing.T) {
	s := newSession(t)
	s.openStore = cannotOpen("keychain unavailable")
	if _, stderr, code := s.run("secret", "delete", "gh"); code != 1 || stderr != "error: keychain unavailable\n" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	s.openStore = failWith("delete denied")
	stdout, stderr, code := s.run("secret", "delete", "gh")
	if code != 1 || stdout != "" || stderr != "error: delete denied\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestSecretDeleteRejectsABadAccount(t *testing.T) {
	s := newSession(t)
	if _, stderr, code := s.run("secret", "delete", "a/b"); code != 1 || !strings.HasPrefix(stderr, "error: ") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestAuthLogoutReportsStoreFailures(t *testing.T) {
	s := newSession(t)
	s.openStore = cannotOpen("keychain unavailable")
	if _, stderr, code := s.run("auth", "logout", "sentry"); code != 1 || stderr != "error: keychain unavailable\n" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	s.openStore = failWith("delete denied")
	stdout, stderr, code := s.run("auth", "logout", "sentry")
	if code != 1 || stdout != "" || stderr != "error: delete denied\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestAuthLogoutRemovesTheStoredLoginOnly(t *testing.T) {
	s := newSession(t)
	_ = s.secrets.Set("oauth.sentry", `{}`)
	_ = s.secrets.Set("sentry", "keep")
	s.run("auth", "logout", "sentry")
	if _, found, _ := s.secrets.Get("oauth.sentry"); found {
		t.Fatal("the login must be gone")
	}
	if got, _, _ := s.secrets.Get("sentry"); got != "keep" {
		t.Fatal("an unrelated secret must stay")
	}
}

func TestAuthLoginStopsWhenTheStoreCannotBeOpened(t *testing.T) {
	s := newSession(t)
	s.openStore = cannotOpen("keychain unavailable")
	config := writeConfig(t, `{"mcpServers":{"sentry":{"url":"https://example.com/mcp","oauth":{}}}}`)
	_, stderr, code := s.run("auth", "login", "sentry", "--config", config)
	if code != 1 || stderr != "error: keychain unavailable\n" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestAuthLoginNamesAnUnknownServer(t *testing.T) {
	s := newSession(t)
	config := writeConfig(t, `{"mcpServers":{}}`)
	_, stderr, code := s.run("auth", "login", "nope", "--config", config)
	if code != 1 || !strings.Contains(stderr, `no server named "nope"`) {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestAnnounceLoginPrintsTheURLToStderr(t *testing.T) {
	var buf bytes.Buffer
	announceLogin(&buf)("https://auth.example/authorize?x=1")
	want := "Opening your browser. If it does not open, visit:\nhttps://auth.example/authorize?x=1\n"
	if buf.String() != want {
		t.Fatalf("got %q", buf.String())
	}
}
