package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/proxy"
	"github.com/henry40408/toolward/internal/store"
)

// signalContext ends on SIGINT or SIGTERM.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// runServe answers the agent on stdin and stdout until the agent closes stdin
// or a termination signal arrives, then shuts every upstream down. Stdout
// carries only the protocol: every log line goes to stderr.
func runServe(p process, inv *invocation) error {
	cfg, err := loadConfig(inv)
	if err != nil {
		return err
	}
	keychain, err := p.newStore()
	if err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	credentials := store.NewCached(keychain, p.stderr)
	running := proxy.FromConfig(proxy.FromConfigOptions{Config: cfg, Store: credentials, Log: p.stderr})
	peer := running.Serve(mcpwire.NewStdioTransport(p.stdin, p.stdout))
	select {
	case <-peer.Done():
	case <-ctx.Done():
	}
	_ = peer.Close()
	running.Shutdown()
	return transportFailure(peer.Err())
}

// transportFailure is the reason the session ended, unless it ended the normal
// way: stdin closed, or a termination signal.
func transportFailure(reason error) error {
	if reason == nil || reason == mcpwire.ErrClosed {
		return nil
	}
	return reason
}
