package mcpwire

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"
)

const helperEnv = "TOOLWARD_MCPWIRE_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "echo":
		runEchoHelper()
	case "stubborn":
		runStubbornHelper()
	case "sigterm":
		runSigtermHelper()
	default:
		os.Exit(m.Run())
	}
}

// runEchoHelper answers every request with its params and leaves when stdin
// ends.
func runEchoHelper() {
	fmt.Fprintln(os.Stderr, "first line")
	fmt.Fprint(os.Stderr, "unterminated")
	peer := NewPeer(NewStdioTransport(os.Stdin, os.Stdout), echoHandler())
	<-peer.Done()
	os.Exit(0)
}

// runStubbornHelper ignores the end of its stdin.
func runStubbornHelper() {
	time.Sleep(time.Minute)
	os.Exit(0)
}

// runSigtermHelper ignores the end of its stdin and reports SIGTERM.
func runSigtermHelper() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	fmt.Fprintln(os.Stderr, "ready")
	<-signals
	fmt.Fprintln(os.Stderr, "got SIGTERM")
	os.Exit(0)
}

type lines struct {
	mu   sync.Mutex
	list []string
}

func (l *lines) add(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = append(l.list, line)
}

func (l *lines) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.list...)
}

func startHelper(t *testing.T, mode string, config CommandConfig) *CommandTransport {
	t.Helper()
	config.Path = os.Args[0]
	config.ExtraEnv = append(config.ExtraEnv, helperEnv+"="+mode)
	transport, err := StartCommand(config)
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

func TestCommandTalksToChildAndRelaysStderr(t *testing.T) {
	var stderr lines
	transport := startHelper(t, "echo", CommandConfig{OnStderrLine: stderr.add})
	peer := NewPeer(transport, nil)

	result, err := peer.Call(context.Background(), "m", json.RawMessage(`[1]`))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"method":"m","params":[1]}`; string(result) != want {
		t.Errorf("result = %s, want %s", result, want)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	got := stderr.snapshot()
	if len(got) != 2 || got[0] != "first line" || got[1] != "unterminated" {
		t.Errorf("stderr lines = %q", got)
	}
}

func TestCommandCloseKillsAChildThatStays(t *testing.T) {
	transport := startHelper(t, "stubborn", CommandConfig{ExitGrace: 100 * time.Millisecond})
	started := time.Now()
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Errorf("Close took %v", elapsed)
	}
	select {
	case <-transport.exited:
	default:
		t.Error("child still running")
	}
}

func TestCommandCloseSendsSIGTERMBeforeKilling(t *testing.T) {
	var stderr lines
	ready := make(chan struct{})
	var once sync.Once
	transport := startHelper(t, "sigterm", CommandConfig{
		ExitGrace: 200 * time.Millisecond,
		OnStderrLine: func(line string) {
			stderr.add(line)
			if line == "ready" {
				once.Do(func() { close(ready) })
			}
		},
	})
	<-ready
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	got := stderr.snapshot()
	if len(got) != 2 || got[1] != "got SIGTERM" {
		t.Errorf("stderr lines = %q", got)
	}
}

func TestStartCommandReportsAMissingProgram(t *testing.T) {
	if _, err := StartCommand(CommandConfig{Path: "/nonexistent/toolward-test"}); err == nil {
		t.Error("expected an error")
	}
}
