package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/mcpwire"
)

func TestGeneralHelpComesFromEveryRouteToIt(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}, {"secret", "--help"}, {"auth", "-h"}} {
		s := newSession(t)
		stdout, stderr, code := s.run(args...)
		if code != 0 || stderr != "" || !strings.Contains(stdout, "Usage: toolward [OPTIONS] <COMMAND>") || !strings.Contains(stdout, "secret set") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
}

func TestHelpOfACommandIsTheHelpFlagOfThatCommand(t *testing.T) {
	s := newSession(t)
	stdout, _, code := s.run("help", "secret", "set")
	if code != 0 || !strings.Contains(stdout, "Usage: toolward secret set <ACCOUNT> [OPTIONS]") {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
}

func TestUsageErrorsNameWhatIsWrong(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{nil, "error: a command is required"},
		{[]string{"bogus"}, "error: unrecognized subcommand 'bogus'"},
		{[]string{"secret"}, "error: 'secret' needs a subcommand"},
		{[]string{"auth", "bogus"}, "error: unrecognized subcommand 'auth bogus'"},
		{[]string{"--nope"}, "error: flag provided but not defined: -nope"},
		{[]string{"--config"}, "error: flag needs an argument: -config"},
		{[]string{"secret", "set"}, "error: the required argument <ACCOUNT> was not provided"},
		{[]string{"secret", "set", "a", "b"}, "error: unexpected argument 'b'"},
		{[]string{"secret", "set", "a", "--nope"}, "error: flag provided but not defined: -nope"},
		{[]string{"check", "--format", "xml"}, `error: invalid value "xml" for flag -format: invalid value "xml" for --format (possible values: text, json)`},
	}
	for _, test := range tests {
		s := newSession(t)
		stdout, stderr, code := s.run(test.args...)
		if code != 2 || stdout != "" || !strings.HasPrefix(stderr, test.want+"\n\nFor more information, try '--help'.\n") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", test.args, code, stdout, stderr)
		}
	}
}

func TestADoubleDashEndsTheFlags(t *testing.T) {
	s := newSession(t)
	s.stdin = "token"
	if _, stderr, code := s.run("secret", "set", "--", "gh"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if got, _, _ := s.secrets.Get("gh"); got != "token" {
		t.Fatalf("stored %q", got)
	}
}

func TestACommandWithoutAConfigFileNamesThePath(t *testing.T) {
	s := newSession(t)
	missing := t.TempDir() + "/missing.json"
	_, stderr, code := s.run("check", "--config", missing)
	if code != 1 || !strings.HasPrefix(stderr, "error: ") || !strings.Contains(stderr, "missing.json") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestRootVersionFlagPrintsTheVersion(t *testing.T) {
	for _, flag := range []string{"--version", "-V"} {
		s := newSession(t)
		stdout, _, code := s.run(flag)
		if code != 0 || !strings.HasPrefix(stdout, "toolward ") {
			t.Errorf("%s: exit %d, stdout %q", flag, code, stdout)
		}
	}
}

// pipe is an os.Pipe whose ends close with the test.
func pipe(t *testing.T) (reader, writer *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	return reader, writer
}

func TestServeAnswersTheAgentUntilStdinCloses(t *testing.T) {
	config := writeConfig(t, `{"mcpServers":{}}`)
	agentToServe, agentWrites := pipe(t)
	agentReads, serveWrites := pipe(t)
	var errBuf syncWriter
	s := newSession(t)

	exit := make(chan int, 1)
	go func() {
		exit <- run(process{
			args:     []string{"serve", "--config", config},
			stdin:    agentToServe,
			stdout:   serveWrites,
			stderr:   &errBuf,
			newStore: s.newStore,
		})
	}()

	agent := mcpwire.NewPeer(mcpwire.NewStdioTransport(agentReads, agentWrites), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := mcpwire.Initialize(ctx, agent, mcpwire.Implementation{Name: "agent", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Call(ctx, "tools/list", nil); err != nil {
		t.Fatal(err)
	}
	_ = agentWrites.Close() // the agent hangs up

	select {
	case code := <-exit:
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, errBuf.String())
		}
	case <-ctx.Done():
		t.Fatal("serve did not stop when stdin closed")
	}
	_ = agent.Close()
}

func TestServeStopsBeforeStartingWhenTheStoreCannotBeOpened(t *testing.T) {
	s := newSession(t)
	s.openStore = cannotOpen("keychain unavailable")
	config := writeConfig(t, `{"mcpServers":{}}`)
	_, stderr, code := s.run("serve", "--config", config)
	if code != 1 || stderr != "error: keychain unavailable\n" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestServeStopsWhenTheConfigIsBroken(t *testing.T) {
	s := newSession(t)
	config := writeConfig(t, `{"mcpServers":`)
	_, stderr, code := s.run("serve", "--config", config)
	if code != 1 || !strings.HasPrefix(stderr, "error: ") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestTransportFailureIgnoresTheNormalEnds(t *testing.T) {
	if transportFailure(nil) != nil || transportFailure(mcpwire.ErrClosed) != nil {
		t.Fatal("a normal end is not a failure")
	}
	reason := os.ErrDeadlineExceeded
	if transportFailure(reason) != reason {
		t.Fatal("another reason must come back")
	}
}

// syncWriter is a log that the test reads while serve still writes to it.
type syncWriter struct {
	mu   sync.Mutex
	data strings.Builder
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.data.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.data.String()
}
