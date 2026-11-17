package mcpwire

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const (
	defaultExitGrace = 3 * time.Second
	// A grandchild that keeps the pipes open must not keep Wait from returning.
	pipeDrainDelay = 2 * time.Second
)

// CommandConfig describes a child process that speaks MCP over stdio.
type CommandConfig struct {
	Path string
	Args []string
	// ExtraEnv is added to the environment of this process.
	ExtraEnv []string
	// OnStderrLine receives each line the child writes to stderr. Stderr is
	// always drained and never inherited.
	OnStderrLine func(line string)
	// ExitGrace is how long Close waits at each step of the shutdown: after
	// closing stdin, and again after SIGTERM. Zero means three seconds.
	ExitGrace time.Duration
}

// CommandTransport talks to a child process over its stdin and stdout.
type CommandTransport struct {
	*StdioTransport
	cmd       *exec.Cmd
	stdin     io.Closer
	exited    chan struct{}
	grace     time.Duration
	closeOnce sync.Once
}

// StartCommand starts the child. It takes no context on purpose: a connect
// timeout must not decide how long the child lives. The child lives until
// Close or until it exits by itself.
func StartCommand(config CommandConfig) (*CommandTransport, error) {
	cmd := exec.Command(config.Path, config.Args...)
	cmd.Env = append(os.Environ(), config.ExtraEnv...)
	cmd.WaitDelay = pipeDrainDelay
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutReader, stdoutWriter := io.Pipe()
	cmd.Stdout = stdoutWriter
	stderr := &lineWriter{emit: config.OnStderrLine}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	transport := &CommandTransport{
		StdioTransport: &StdioTransport{
			reader: bufio.NewReader(stdoutReader),
			writer: stdin,
			closer: stdoutReader,
		},
		cmd:    cmd,
		stdin:  stdin,
		exited: make(chan struct{}),
		grace:  graceOrDefault(config.ExitGrace),
	}
	go transport.reap(stdoutWriter, stderr)
	return transport, nil
}

func graceOrDefault(grace time.Duration) time.Duration {
	if grace > 0 {
		return grace
	}
	return defaultExitGrace
}

// reap waits for the child, then ends the streams its output flowed through.
func (t *CommandTransport) reap(stdout *io.PipeWriter, stderr *lineWriter) {
	_ = t.cmd.Wait()
	stderr.flush()
	_ = stdout.Close()
	close(t.exited)
}

// Close shuts the child down like rmcp: close stdin, wait, SIGTERM, wait,
// then kill. SIGTERM lets wrappers such as npx stop their own children.
func (t *CommandTransport) Close() error {
	t.closeOnce.Do(t.shutDown)
	return nil
}

func (t *CommandTransport) shutDown() {
	_ = t.stdin.Close()
	if !t.exitsWithinGrace() {
		_ = t.cmd.Process.Signal(syscall.SIGTERM)
		if !t.exitsWithinGrace() {
			_ = t.cmd.Process.Kill()
			<-t.exited
		}
	}
	_ = t.closer.Close()
}

func (t *CommandTransport) exitsWithinGrace() bool {
	timer := time.NewTimer(t.grace)
	defer timer.Stop()
	select {
	case <-t.exited:
		return true
	case <-timer.C:
		return false
	}
}

// lineWriter turns the stream written to it into lines.
type lineWriter struct {
	emit func(line string)
	buf  bytes.Buffer
}

func (w *lineWriter) Write(data []byte) (int, error) {
	w.buf.Write(data)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			w.buf.WriteString(line)
			break
		}
		w.emitLine(line)
	}
	return len(data), nil
}

func (w *lineWriter) flush() {
	if w.buf.Len() == 0 {
		return
	}
	w.emitLine(w.buf.String())
	w.buf.Reset()
}

func (w *lineWriter) emitLine(line string) {
	if w.emit == nil {
		return
	}
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	w.emit(line)
}
