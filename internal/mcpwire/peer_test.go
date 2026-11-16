package mcpwire

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// pipePair connects two transports back to back.
func pipePair() (*StdioTransport, *StdioTransport) {
	bRead, aWrite := io.Pipe()
	aRead, bWrite := io.Pipe()
	return NewStdioTransport(aRead, aWrite), NewStdioTransport(bRead, bWrite)
}

type funcHandler struct {
	request      func(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error)
	notification func(method string, params json.RawMessage)
}

func (h funcHandler) HandleRequest(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	return h.request(ctx, method, params)
}

func (h funcHandler) HandleNotification(_ context.Context, method string, params json.RawMessage) {
	if h.notification != nil {
		h.notification(method, params)
	}
}

func connect(t *testing.T, client, server Handler) (*Peer, *Peer) {
	t.Helper()
	a, b := pipePair()
	clientPeer := NewPeer(a, client)
	serverPeer := NewPeer(b, server)
	t.Cleanup(func() {
		_ = clientPeer.Close()
		_ = serverPeer.Close()
	})
	return clientPeer, serverPeer
}

func echoHandler() Handler {
	return funcHandler{request: func(_ context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"method":"` + method + `","params":` + string(params) + `}`), nil
	}}
}

func TestCallRoundTrip(t *testing.T) {
	client, _ := connect(t, nil, echoHandler())
	result, err := client.Call(context.Background(), "tools/list", json.RawMessage(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"method":"tools/list","params":{"a":1}}`; string(result) != want {
		t.Errorf("result = %s, want %s", result, want)
	}
}

func TestConcurrentCalls(t *testing.T) {
	client, _ := connect(t, nil, echoHandler())
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			params, _ := json.Marshal(i)
			result, err := client.Call(context.Background(), "m", params)
			if err != nil {
				t.Error(err)
				return
			}
			if want := `{"method":"m","params":` + string(params) + `}`; string(result) != want {
				t.Errorf("result = %s, want %s", result, want)
			}
		}()
	}
	wg.Wait()
}

func TestHandlerErrorKeepsCodeAndData(t *testing.T) {
	server := funcHandler{request: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return nil, &Error{Code: CodeInvalidParams, Message: "bad", Data: json.RawMessage(`{"x":1}`)}
	}}
	client, _ := connect(t, nil, server)
	_, err := client.Call(context.Background(), "m", nil)
	var rpcErr *Error
	if !errors.As(err, &rpcErr) {
		t.Fatalf("err = %v, want *Error", err)
	}
	if rpcErr.Code != CodeInvalidParams || rpcErr.Message != "bad" || string(rpcErr.Data) != `{"x":1}` {
		t.Errorf("error = %+v", rpcErr)
	}
	if want := `Mcp error: -32602: bad({"x":1})`; rpcErr.Error() != want {
		t.Errorf("text = %q, want %q", rpcErr.Error(), want)
	}
}

func TestPlainHandlerErrorBecomesInternalError(t *testing.T) {
	server := funcHandler{request: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return nil, errors.New("broke")
	}}
	client, _ := connect(t, nil, server)
	_, err := client.Call(context.Background(), "m", nil)
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != CodeInternalError || rpcErr.Message != "broke" {
		t.Errorf("err = %v", err)
	}
}

func TestInvalidResultBecomesInternalError(t *testing.T) {
	server := funcHandler{request: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"a":`), nil
	}}
	client, _ := connect(t, nil, server)
	_, err := client.Call(context.Background(), "m", nil)
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != CodeInternalError {
		t.Errorf("err = %v", err)
	}
}

func TestClientAnswersPingAndRefusesOtherRequests(t *testing.T) {
	_, server := connect(t, nil, echoHandler())
	if _, err := server.Call(context.Background(), "ping", nil); err != nil {
		t.Fatalf("ping: %v", err)
	}
	_, err := server.Call(context.Background(), "roots/list", nil)
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != CodeMethodNotFound {
		t.Errorf("err = %v, want method not found", err)
	}
}

func TestNotificationsArriveInOrder(t *testing.T) {
	got := make(chan string, 10)
	client := funcHandler{
		request: func(context.Context, string, json.RawMessage) (json.RawMessage, error) { return nil, nil },
		notification: func(method string, _ json.RawMessage) {
			got <- method
		},
	}
	_, server := connect(t, client, echoHandler())
	for _, method := range []string{"a", "b", "c"} {
		if err := server.Notify(method, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"a", "b", "c"} {
		if method := <-got; method != want {
			t.Errorf("method = %q, want %q", method, want)
		}
	}
}

func TestCancelledCallStopsTheRemoteHandler(t *testing.T) {
	started := make(chan struct{})
	handlerCtxEnded := make(chan error, 1)
	server := funcHandler{request: func(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		close(started)
		<-ctx.Done()
		handlerCtxEnded <- context.Cause(ctx)
		return nil, ctx.Err()
	}}
	client, _ := connect(t, nil, server)

	ctx, cancel := context.WithCancelCause(context.Background())
	errs := make(chan error, 1)
	go func() {
		_, err := client.Call(ctx, "slow", nil)
		errs <- err
	}()
	<-started
	cancel(errors.New("cancelled by the client"))

	if err := <-errs; !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context canceled", err)
	}
	select {
	case cause := <-handlerCtxEnded:
		if !errors.Is(cause, errCancelledByPeer) {
			t.Errorf("handler ctx cause = %v", cause)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler was not told to stop")
	}
}

func TestCancelNotificationCarriesRequestIDAndReason(t *testing.T) {
	a, b := pipePair()
	client := NewPeer(a, nil)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithCancelCause(context.Background())
	go func() { _, _ = client.Call(ctx, "slow", nil) }()
	request := readMessage(t, b)
	cancel(errors.New("cancelled by the client"))
	note := readMessage(t, b)

	if note.Method != methodCancelled {
		t.Fatalf("method = %q", note.Method)
	}
	want := `{"reason":"cancelled by the client","requestId":` + string(request.ID) + `}`
	if got := string(note.Params); got != want {
		t.Errorf("params = %s, want %s", got, want)
	}
}

func readMessage(t *testing.T, transport Transport) message {
	t.Helper()
	line, err := transport.Read()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := decodeMessage(line)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestCallWithEndedContextSendsNothing(t *testing.T) {
	client, _ := connect(t, nil, echoHandler())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Call(ctx, "m", nil); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestClosingTheTransportFailsPendingCalls(t *testing.T) {
	started := make(chan struct{})
	server := funcHandler{request: func(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	client, serverPeer := connect(t, nil, server)
	errs := make(chan error, 1)
	go func() {
		_, err := client.Call(context.Background(), "slow", nil)
		errs <- err
	}()
	<-started
	_ = serverPeer.Close()

	select {
	case err := <-errs:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("err = %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pending call was not failed")
	}
	<-client.Done()
	if !client.Closed() {
		t.Error("peer not closed")
	}
	if _, err := client.Call(context.Background(), "m", nil); !errors.Is(err, ErrClosed) {
		t.Errorf("call on closed peer: %v", err)
	}
	if err := client.Notify("n", nil); !errors.Is(err, ErrClosed) {
		t.Errorf("notify on closed peer: %v", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	client, _ := connect(t, nil, echoHandler())
	_ = client.Close()
	_ = client.Close()
	select {
	case <-client.Done():
	default:
		t.Error("Done not closed")
	}
}

func TestHandlerSeesItsPeer(t *testing.T) {
	seen := make(chan *Peer, 1)
	server := funcHandler{request: func(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		seen <- PeerFromContext(ctx)
		return nil, nil
	}}
	client, serverPeer := connect(t, nil, server)
	if _, err := client.Call(context.Background(), "m", nil); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != serverPeer {
		t.Error("handler context does not carry its peer")
	}
}

func TestMalformedLinesAreIgnored(t *testing.T) {
	a, b := pipePair()
	server := NewPeer(b, echoHandler())
	t.Cleanup(func() { _ = server.Close() })
	if err := a.Write([]byte("not json")); err != nil {
		t.Fatal(err)
	}
	if err := a.Write([]byte(`{"jsonrpc":"2.0","id":7,"method":"m","params":{}}`)); err != nil {
		t.Fatal(err)
	}
	if answer := readMessage(t, a); string(answer.ID) != "7" {
		t.Errorf("answer id = %s", answer.ID)
	}
}
