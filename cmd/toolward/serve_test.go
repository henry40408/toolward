package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/testing/fakeupstream"
)

// runningServe is a `toolward serve` process that the test talks to.
type runningServe struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan string
	stderr *bytes.Buffer
}

func startServe(t *testing.T) *runningServe {
	t.Helper()
	requireCredentialStore(t)
	config := writeConfig(t, fmt.Sprintf(`{"mcpServers":{
		"fake":{"command":%q,"env":{%q:"1"}},
		"broken":{"command":"/nonexistent/toolward-test-binary"}
	}}`, os.Args[0], fakeupstream.EnvSwitch))
	cmd := toolwardCommand(context.Background(), "--config", config, "serve")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// With a file as stdout, Wait does not cut off what is still unread.
	cmd.Stdout = stdoutWriter
	server := &runningServe{cmd: cmd, stdin: stdin, lines: make(chan string, 100), stderr: &bytes.Buffer{}}
	cmd.Stderr = server.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = stdoutWriter.Close()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(nil, 1<<20)
		for scanner.Scan() {
			server.lines <- scanner.Text()
		}
		close(server.lines)
	}()
	return server
}

func (s *runningServe) send(t *testing.T, message string) {
	t.Helper()
	if _, err := io.WriteString(s.stdin, message+"\n"); err != nil {
		t.Fatal(err)
	}
}

// next returns the next line of stdout, which must be one JSON-RPC message.
func (s *runningServe) next(t *testing.T) map[string]any {
	t.Helper()
	select {
	case line, open := <-s.lines:
		if !open {
			t.Fatalf("stdout closed; stderr: %s", s.stderr.String())
		}
		var message map[string]any
		if err := json.Unmarshal([]byte(line), &message); err != nil || message["jsonrpc"] != "2.0" {
			t.Fatalf("stdout holds more than the protocol: %q", line)
		}
		return message
	case <-time.After(processWait):
		t.Fatalf("no answer; stderr: %s", s.stderr.String())
		return nil
	}
}

// handshake runs initialize and lists the tools, with stdin still open.
func (s *runningServe) handshake(t *testing.T) []any {
	t.Helper()
	s.send(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	if reply := s.next(t); reply["id"] != float64(1) || reply["error"] != nil {
		t.Fatalf("initialize: %v", reply)
	}
	s.send(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	s.send(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	reply := s.next(t)
	result, _ := reply["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	return tools
}

func (s *runningServe) waitForExit(t *testing.T) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case <-done:
		return s.cmd.ProcessState.ExitCode()
	case <-time.After(processWait):
		t.Fatalf("toolward did not stop; stderr: %s", s.stderr.String())
		return -1
	}
}

func TestServeWritesOnlyProtocolBytesToStdout(t *testing.T) {
	server := startServe(t)
	if tools := server.handshake(t); len(tools) == 0 {
		t.Fatalf("no tools; stderr: %s", server.stderr.String())
	}
	// Closing stdin is how the agent ends the session.
	_ = server.stdin.Close()
	if code := server.waitForExit(t); code != 0 {
		t.Fatalf("exit %d; stderr: %s", code, server.stderr.String())
	}
	for line := range server.lines {
		t.Errorf("stdout holds more than the answers: %q", line)
	}
	if !strings.Contains(server.stderr.String(), "toolward: ") {
		t.Fatalf("the broken upstream left no log on stderr: %q", server.stderr.String())
	}
}

func TestServeStopsOnSIGTERM(t *testing.T) {
	server := startServe(t)
	server.handshake(t)
	if err := server.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := server.waitForExit(t); code != 0 {
		t.Fatalf("exit %d; stderr: %s", code, server.stderr.String())
	}
}
