// Package upstream is one upstream MCP server, connected lazily and
// reconnected on demand.
package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/henry40408/toolward/internal/cache"
	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/redact"
)

const (
	// DefaultRetryAfter is how long a failed upstream is left alone before the
	// next connection attempt.
	DefaultRetryAfter = 30 * time.Second
	// DefaultConnectTimeout bounds spawning a server and completing the MCP
	// handshake.
	DefaultConnectTimeout = 60 * time.Second
	// DefaultListTimeout is how long a list request may take before the
	// upstream is skipped.
	DefaultListTimeout = 10 * time.Second
)

// Config describes one upstream. Zero timeouts mean the defaults.
type Config struct {
	Name      string
	Connector Connector
	Hub       *Hub
	// Log gets the diagnostics. It is stderr in the real program.
	Log            io.Writer
	ListTimeout    time.Duration
	ConnectTimeout time.Duration
	RetryAfter     time.Duration
	// Now is the clock. Tests replace it.
	Now func() time.Time
}

type state int

const (
	stateIdle state = iota
	stateRunning
	stateFailed
	// stateClosed is after Shutdown: no new child may be started.
	stateClosed
)

// Upstream is one server, connected on first use.
type Upstream struct {
	name      string
	connector Connector
	handler   *Handler
	log       io.Writer
	now       func() time.Time

	listTimeout    time.Duration
	connectTimeout time.Duration
	retryAfter     time.Duration

	// gate is held while the state changes, also across a connect. It is a
	// channel so that waiting for it can be given up when a context ends.
	gate     chan struct{}
	state    state
	session  *mcpwire.Session
	failedAt time.Time
	reason   string

	toolsMu sync.Mutex
	tools   *toolMap
}

// New returns an upstream that has not connected yet.
func New(config Config) *Upstream {
	u := &Upstream{
		name:           config.Name,
		connector:      config.Connector,
		log:            config.Log,
		now:            config.Now,
		listTimeout:    durationOr(config.ListTimeout, DefaultListTimeout),
		connectTimeout: durationOr(config.ConnectTimeout, DefaultConnectTimeout),
		retryAfter:     durationOr(config.RetryAfter, DefaultRetryAfter),
		gate:           make(chan struct{}, 1),
	}
	if u.now == nil {
		u.now = time.Now
	}
	u.handler = &Handler{hub: config.Hub, forgetTools: u.forgetTools}
	return u
}

func durationOr(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

// Name is the server name.
func (u *Upstream) Name() string {
	return u.name
}

func (u *Upstream) acquire(ctx context.Context) error {
	select {
	case u.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (u *Upstream) tryAcquire() bool {
	select {
	case u.gate <- struct{}{}:
		return true
	default:
		return false
	}
}

func (u *Upstream) release() {
	<-u.gate
}

// seconds renders a duration like Rust's f32 seconds: "10", "1.5".
func seconds(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', -1, 32)
}

// Bounded runs a list request, giving up after the list timeout. Errors are
// redacted, so they are safe to show.
func Bounded[T any](ctx context.Context, u *Upstream, request func(ctx context.Context) (T, error)) (T, error) {
	boundedCtx, cancel := context.WithTimeout(ctx, u.listTimeout)
	defer cancel()
	result, err := request(boundedCtx)
	if err == nil {
		return result, nil
	}
	var zero T
	if boundedCtx.Err() != nil && ctx.Err() == nil {
		return zero, fmt.Errorf("no response to a list request within %ss", seconds(u.listTimeout))
	}
	return zero, errors.New(u.Redact(err.Error()))
}

// Redact masks the secrets of this upstream in text.
func (u *Upstream) Redact(text string) string {
	return redact.Redact(text, u.handler.Secrets())
}

// RedactResult masks the secrets of this upstream in a result on its way to
// the agent.
func (u *Upstream) RedactResult(result json.RawMessage) (json.RawMessage, error) {
	return redact.Value(result, u.handler.Secrets())
}

// RedactListed is like RedactResult, for the items of a listing.
func (u *Upstream) RedactListed(listed cache.Listed[json.RawMessage]) (cache.Listed[json.RawMessage], error) {
	secrets := u.handler.Secrets()
	items := make([]json.RawMessage, 0, len(listed.Items))
	for _, item := range listed.Items {
		masked, err := redact.Value(item, secrets)
		if err != nil {
			return cache.Listed[json.RawMessage]{}, err
		}
		items = append(items, masked)
	}
	return cache.Listed[json.RawMessage]{Items: items, Hint: listed.Hint}, nil
}

// alive says whether the running connection can still be used.
func (u *Upstream) alive() bool {
	return u.state == stateRunning && !u.session.Peer.Closed()
}

// ListPeer is like Peer, for a list request: connecting may take no longer
// than the list timeout, so one hung upstream cannot hold up the whole
// listing. A connection that times out counts as a failure and is not tried
// again for the retry time.
func (u *Upstream) ListPeer(ctx context.Context) (*mcpwire.Session, error) {
	listCtx, cancel := context.WithTimeout(ctx, u.listTimeout)
	defer cancel()
	session, err := u.Peer(listCtx)
	if err == nil {
		return session, nil
	}
	if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		return nil, err
	}
	reason := fmt.Sprintf("no connection within %ss", seconds(u.listTimeout))
	u.recordTimeout(reason)
	return nil, errors.New(reason)
}

// recordTimeout remembers a timed out connection as a failure. Another request
// that is still connecting holds the gate and records its own outcome.
func (u *Upstream) recordTimeout(reason string) {
	if !u.tryAcquire() {
		return
	}
	defer u.release()
	if u.timedOutStateMayFail() {
		u.fail(reason)
	}
}

func (u *Upstream) timedOutStateMayFail() bool {
	switch u.state {
	case stateIdle:
		return true
	case stateFailed:
		return u.now().Sub(u.failedAt) >= u.retryAfter
	case stateRunning:
		// A connection that died on its own, then hung on reconnect.
		return !u.alive()
	default:
		return false
	}
}

func (u *Upstream) fail(reason string) {
	u.state = stateFailed
	u.session = nil
	u.failedAt = u.now()
	u.reason = reason
}

// Peer returns the live connection, connecting first when needed. A failure
// is remembered for the retry time so a broken upstream does not slow down
// every request. Ending ctx gives up the connecting and changes no state.
func (u *Upstream) Peer(ctx context.Context) (*mcpwire.Session, error) {
	if err := u.acquire(ctx); err != nil {
		return nil, err
	}
	defer u.release()
	if session, done, err := u.reuse(); done {
		return session, err
	}
	return u.connect(ctx)
}

// reuse answers from the state when no new connection is due.
func (u *Upstream) reuse() (session *mcpwire.Session, done bool, err error) {
	switch {
	case u.alive():
		return u.session, true, nil
	case u.state == stateFailed && u.now().Sub(u.failedAt) < u.retryAfter:
		return nil, true, errors.New(u.reason)
	case u.state == stateClosed:
		return nil, true, errors.New("proxy is shutting down")
	}
	return nil, false, nil
}

func (u *Upstream) connect(ctx context.Context) (*mcpwire.Session, error) {
	connectCtx, cancel := context.WithTimeout(ctx, u.connectTimeout)
	defer cancel()
	session, err := u.connector.Connect(connectCtx, u.handler)
	if err != nil {
		return nil, u.connectFailed(ctx, connectCtx, err)
	}
	u.state = stateRunning
	u.session = session
	return session, nil
}

func (u *Upstream) connectFailed(ctx, connectCtx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	reason := err.Error()
	if connectCtx.Err() != nil {
		reason = fmt.Sprintf("no response within %ds", int(u.connectTimeout.Seconds()))
	}
	u.fail(reason)
	return errors.New(reason)
}

// Shutdown closes the connection. The upstream refuses new connections
// afterwards.
func (u *Upstream) Shutdown() {
	u.gate <- struct{}{}
	defer u.release()
	session := u.session
	u.state = stateClosed
	u.session = nil
	if session != nil {
		_ = session.Peer.Close()
	}
}
