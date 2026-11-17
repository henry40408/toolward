package mcpwire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
)

const (
	methodPing      = "ping"
	methodCancelled = "notifications/cancelled"
)

var errCancelledByPeer = errors.New("cancelled by the peer")

// Handler answers what the other side sends. Notifications are delivered one
// at a time and in order on the goroutine that reads the connection, so a
// handler must not wait for a call on the same peer to finish.
type Handler interface {
	HandleRequest(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error)
	HandleNotification(ctx context.Context, method string, params json.RawMessage)
}

// ClientHandler is the handler of a client: it answers ping and refuses every
// other request.
type ClientHandler struct {
	OnNotification func(method string, params json.RawMessage)
}

// HandleRequest answers ping with an empty result.
func (h ClientHandler) HandleRequest(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
	if method == methodPing {
		return json.RawMessage("{}"), nil
	}
	return nil, MethodNotFound(method)
}

// HandleNotification passes the notification on, when someone listens.
func (h ClientHandler) HandleNotification(_ context.Context, method string, params json.RawMessage) {
	if h.OnNotification != nil {
		h.OnNotification(method, params)
	}
}

type peerContextKey struct{}

// PeerFromContext returns the peer a handler is serving. It is nil outside a
// handler.
func PeerFromContext(ctx context.Context) *Peer {
	peer, _ := ctx.Value(peerContextKey{}).(*Peer)
	return peer
}

type response struct {
	result json.RawMessage
	err    error
}

// Peer is one end of a JSON-RPC connection. It sends requests and
// notifications and answers the ones it receives.
type Peer struct {
	transport Transport
	handler   Handler
	nextID    atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	pending  map[string]chan response
	inbound  map[string]context.CancelCauseFunc
	closeErr error

	done      chan struct{}
	shutOnce  sync.Once
	closeOnce sync.Once
}

// NewPeer starts reading the transport at once. A nil handler gives a plain
// client.
func NewPeer(transport Transport, handler Handler) *Peer {
	if handler == nil {
		handler = ClientHandler{}
	}
	peer := &Peer{
		transport: transport,
		handler:   handler,
		pending:   map[string]chan response{},
		inbound:   map[string]context.CancelCauseFunc{},
		done:      make(chan struct{}),
	}
	peer.ctx, peer.cancel = context.WithCancel(context.WithValue(context.Background(), peerContextKey{}, peer))
	go peer.readLoop()
	return peer
}

// Done is closed when the connection has ended.
func (p *Peer) Done() <-chan struct{} {
	return p.done
}

// Closed reports whether the connection has ended.
func (p *Peer) Closed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// Err says why the connection ended. It is nil while the connection is open.
func (p *Peer) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeErr
}

// Close ends the connection and fails every call still waiting.
func (p *Peer) Close() error {
	err := p.closeTransport()
	p.shutdown(nil)
	return err
}

func (p *Peer) closeTransport() error {
	var err error
	p.closeOnce.Do(func() { err = p.transport.Close() })
	return err
}

// Call sends a request and waits for its answer. When ctx ends first, the
// other side is told to stop and ctx's error is returned.
func (p *Peer) Call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id := json.RawMessage(strconv.FormatInt(p.nextID.Add(1), 10))
	waiter, err := p.register(string(id))
	if err != nil {
		return nil, err
	}
	request, err := encodeRequest(id, method, params)
	if err == nil {
		err = p.send(ctx, request)
	}
	if err != nil {
		p.forget(string(id))
		return nil, err
	}
	return p.await(ctx, id, waiter)
}

func (p *Peer) await(ctx context.Context, id json.RawMessage, waiter chan response) (json.RawMessage, error) {
	select {
	case answer := <-waiter:
		return answer.result, answer.err
	case <-ctx.Done():
		p.forget(string(id))
		p.cancelRemote(id, context.Cause(ctx))
		return nil, ctx.Err()
	case <-p.done:
		p.forget(string(id))
		select {
		case answer := <-waiter:
			return answer.result, answer.err
		default:
			return nil, p.Err()
		}
	}
}

func (p *Peer) register(key string) (chan response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closeErr != nil || p.Closed() {
		return nil, p.closedError()
	}
	waiter := make(chan response, 1)
	p.pending[key] = waiter
	return waiter, nil
}

func (p *Peer) forget(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, key)
}

func (p *Peer) cancelRemote(id json.RawMessage, cause error) {
	params := map[string]any{"requestId": id}
	if cause != nil && !errors.Is(cause, context.Canceled) {
		params["reason"] = cause.Error()
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return
	}
	_ = p.Notify(methodCancelled, raw)
}

// Notify sends a notification.
func (p *Peer) Notify(method string, params json.RawMessage) error {
	if p.Closed() {
		return p.Err()
	}
	notification, err := encodeNotification(method, params)
	if err != nil {
		return err
	}
	return p.send(context.Background(), notification)
}

// ContextWriter is implemented by transports whose Write can block on the
// network, such as HTTP. A request that waits for its answer passes its
// context, so giving up on the request also gives up on the write.
type ContextWriter interface {
	WriteContext(ctx context.Context, message []byte) error
}

func (p *Peer) send(ctx context.Context, data []byte) error {
	if writer, ok := p.transport.(ContextWriter); ok {
		return writer.WriteContext(ctx, data)
	}
	return p.transport.Write(data)
}

// closedError must be called with p.mu held or after done is closed.
func (p *Peer) closedError() error {
	if p.closeErr != nil {
		return p.closeErr
	}
	return ErrClosed
}

func (p *Peer) readLoop() {
	var readErr error
	for {
		raw, err := p.transport.Read()
		if err != nil {
			readErr = err
			break
		}
		p.dispatch(raw)
	}
	p.shutdown(readErr)
	_ = p.closeTransport()
}

// shutdown runs once. The first reason wins.
func (p *Peer) shutdown(readErr error) {
	p.shutOnce.Do(func() {
		p.mu.Lock()
		p.closeErr = closeReason(readErr)
		p.mu.Unlock()
		close(p.done)
		p.cancel()
	})
}

func closeReason(readErr error) error {
	if readErr == nil || errors.Is(readErr, io.EOF) {
		return ErrClosed
	}
	return fmt.Errorf("%w: %w", ErrClosed, readErr)
}

func (p *Peer) dispatch(raw []byte) {
	msg, err := decodeMessage(raw)
	if err != nil {
		return
	}
	switch msg.kind() {
	case kindResponse:
		p.deliver(msg)
	case kindRequest:
		p.serve(msg)
	case kindNotification:
		p.notified(msg)
	}
}

func (p *Peer) deliver(msg message) {
	key := idKey(msg.ID)
	p.mu.Lock()
	waiter, ok := p.pending[key]
	delete(p.pending, key)
	p.mu.Unlock()
	if !ok {
		return
	}
	if msg.Error != nil {
		waiter <- response{err: msg.Error}
		return
	}
	waiter <- response{result: msg.Result}
}

func (p *Peer) notified(msg message) {
	if msg.Method == methodCancelled {
		p.cancelInbound(msg.Params)
		return
	}
	p.handler.HandleNotification(p.ctx, msg.Method, msg.Params)
}

func (p *Peer) cancelInbound(params json.RawMessage) {
	var fields struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(params, &fields) != nil || len(fields.RequestID) == 0 {
		return
	}
	p.mu.Lock()
	cancel := p.inbound[idKey(fields.RequestID)]
	p.mu.Unlock()
	if cancel != nil {
		cancel(errCancelledByPeer)
	}
}

func (p *Peer) serve(msg message) {
	key := idKey(msg.ID)
	ctx, cancel := context.WithCancelCause(p.ctx)
	p.mu.Lock()
	p.inbound[key] = cancel
	p.mu.Unlock()
	go func() {
		defer cancel(nil)
		result, err := p.runHandler(ctx, msg)
		p.mu.Lock()
		delete(p.inbound, key)
		p.mu.Unlock()
		if errors.Is(context.Cause(ctx), errCancelledByPeer) {
			return
		}
		answer, encodeErr := encodeAnswer(msg.ID, result, err)
		if encodeErr == nil {
			_ = p.send(context.Background(), answer)
		}
	}()
}

// runHandler turns a panic in the handler into an internal error, so one bad
// request does not stop the process.
func (p *Peer) runHandler(ctx context.Context, msg message) (result json.RawMessage, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result, err = nil, InternalError(fmt.Sprintf("handler panicked: %v", recovered))
		}
	}()
	return p.handler.HandleRequest(ctx, msg.Method, msg.Params)
}

func encodeAnswer(id json.RawMessage, result json.RawMessage, err error) ([]byte, error) {
	if err != nil {
		return encodeError(id, asError(err))
	}
	data, encodeErr := encodeResult(id, result)
	if encodeErr != nil {
		return encodeError(id, InternalError("the result is not valid JSON"))
	}
	return data, nil
}
