package mcpwire

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type seenRequest struct {
	Method string
	Header http.Header
	Body   message
}

// httpStub is a streamable HTTP server whose POST answers a test decides.
type httpStub struct {
	*httptest.Server
	mu       sync.Mutex
	requests []seenRequest
}

func newHTTPStub(t *testing.T, answer func(w http.ResponseWriter, r *http.Request, msg message)) *httpStub {
	t.Helper()
	stub := &httpStub{}
	stub.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		msg, _ := decodeMessage(body)
		stub.mu.Lock()
		stub.requests = append(stub.requests, seenRequest{Method: r.Method, Header: r.Header.Clone(), Body: msg})
		stub.mu.Unlock()
		answer(w, r, msg)
	}))
	t.Cleanup(func() {
		stub.CloseClientConnections()
		stub.Close()
	})
	return stub
}

func (s *httpStub) seen(method string) []seenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	var matching []seenRequest
	for _, request := range s.requests {
		if request.Method == method {
			matching = append(matching, request)
		}
	}
	return matching
}

func writeJSONResult(w http.ResponseWriter, id json.RawMessage, result string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(id)+`,"result":`+result+`}`)
}

func writeEventResult(w http.ResponseWriter, id json.RawMessage, result string) {
	w.Header().Set("Content-Type", "text/event-stream")
	_, _ = io.WriteString(w, "id: 1\ndata:\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":"+string(id)+",\"result\":"+result+"}\n\n")
}

const initializeResult = `{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"stub","version":"1"}}`

func newHTTPPeer(t *testing.T, config HTTPConfig, handler Handler) *Peer {
	t.Helper()
	peer := NewPeer(NewHTTPTransport(config), handler)
	t.Cleanup(func() { _ = peer.Close() })
	return peer
}

func shortContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestHTTPSessionVersionAndServerStream(t *testing.T) {
	pushed := make(chan string, 1)
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, msg message) {
		switch {
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case msg.Method == "initialize":
			w.Header().Set("Mcp-Session-Id", "abc")
			writeEventResult(w, msg.ID, initializeResult)
		case msg.kind() == kindNotification:
			w.WriteHeader(http.StatusAccepted)
		default:
			writeJSONResult(w, msg.ID, `{"tools":[]}`)
		}
	})
	handler := ClientHandler{OnNotification: func(method string, _ json.RawMessage) { pushed <- method }}
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, handler)

	session, err := Initialize(shortContext(t), peer, Implementation{Name: "test", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Call(shortContext(t), "tools/list", nil); err != nil {
		t.Fatal(err)
	}
	select {
	case method := <-pushed:
		if method != "notifications/tools/list_changed" {
			t.Errorf("method = %q", method)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the notification of the server stream never arrived")
	}

	posts := stub.seen(http.MethodPost)
	if posts[0].Header.Get("Mcp-Session-Id") != "" || posts[0].Header.Get("Mcp-Protocol-Version") != "" {
		t.Errorf("initialize carried session headers: %v", posts[0].Header)
	}
	last := posts[len(posts)-1]
	if last.Header.Get("Mcp-Session-Id") != "abc" || last.Header.Get("Mcp-Protocol-Version") != "2025-11-25" {
		t.Errorf("tools/list headers = %v", last.Header)
	}
	if last.Header.Get("Mcp-Method") != "" {
		t.Errorf("2025-11-25 has no Mcp-Method header: %v", last.Header)
	}
	if got := last.Header.Get("Accept"); got != "application/json, text/event-stream" {
		t.Errorf("Accept = %q", got)
	}

	_ = peer.Close()
	deletes := stub.seen(http.MethodDelete)
	if len(deletes) != 1 || deletes[0].Header.Get("Mcp-Session-Id") != "abc" {
		t.Errorf("deletes = %+v", deletes)
	}
}

func TestHTTPStatelessRequestsNameTheirMethodAndTarget(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, msg message) {
		if msg.Method == "server/discover" {
			writeJSONResult(w, msg.ID, `{"supportedVersions":["2026-07-28"],"capabilities":{}}`)
			return
		}
		writeJSONResult(w, msg.ID, `{}`)
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)
	session, err := Discover(shortContext(t), peer, Implementation{Name: "test", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Call(shortContext(t), "tools/call", json.RawMessage(`{"name":"héllo"}`)); err != nil {
		t.Fatal(err)
	}

	header := stub.seen(http.MethodPost)[1].Header
	want := map[string]string{
		"Mcp-Protocol-Version": "2026-07-28",
		"Mcp-Method":           "tools/call",
		"Mcp-Name":             "=?base64?aMOpbGxv?=",
	}
	for name, value := range want {
		if got := header.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

func TestHTTPUnauthorizedWithAChallengeAsksForAuthorization(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, _ message) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://x/meta"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)

	_, err := peer.Call(shortContext(t), "ping", nil)
	var required *AuthorizationRequiredError
	if !errors.As(err, &required) || !strings.Contains(required.Challenge, "resource_metadata") {
		t.Errorf("err = %v", err)
	}
	if !IsAuthorizationRequired(err) {
		t.Error("IsAuthorizationRequired = false")
	}
}

func TestHTTPUnauthorizedWithoutAChallengeIsAnHTTPError(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, _ message) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "who are you")
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)

	_, err := peer.Call(shortContext(t), "ping", nil)
	if err == nil || err.Error() != "HTTP 401 Unauthorized: who are you" || IsAuthorizationRequired(err) {
		t.Errorf("err = %v", err)
	}
}

func TestHTTPServerErrorsKeepTheBodyOut(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, _ message) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "echo "+r.Header.Get("Authorization"))
	})
	headers := http.Header{"Authorization": {"Bearer s3cr3t"}}
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL, Headers: headers}, nil)

	_, err := peer.Call(shortContext(t), "ping", nil)
	if err == nil || err.Error() != "HTTP 500" {
		t.Errorf("err = %v", err)
	}
}

func TestHTTPJSONRPCErrorInAFailedResponseReachesTheCaller(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, msg message) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(msg.ID)+`,"error":{"code":-32020,"message":"mismatch"}}`)
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)

	_, err := peer.Call(shortContext(t), "ping", nil)
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != CodeHeaderMismatch {
		t.Errorf("err = %v", err)
	}
}

func TestHTTPJSONRPCErrorWithAnotherIDIsAnHTTPError(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, _ message) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"bad"}}`)
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)

	_, err := peer.Call(shortContext(t), "ping", nil)
	var status *HTTPStatusError
	if !errors.As(err, &status) || status.Status != http.StatusBadRequest {
		t.Errorf("err = %v", err)
	}
}

func TestHTTPAForgottenSessionEndsTheConnection(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, msg message) {
		switch msg.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "abc")
			writeJSONResult(w, msg.ID, initializeResult)
		case "tools/list":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)
	session, err := Initialize(shortContext(t), peer, Implementation{Name: "test", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = session.Call(shortContext(t), "tools/list", nil)
	if !errors.Is(err, ErrSessionExpired) {
		t.Errorf("err = %v", err)
	}
	select {
	case <-peer.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the peer stayed open")
	}
	if got := len(stub.seen(http.MethodDelete)); got != 0 {
		t.Errorf("deleted the forgotten session %d times", got)
	}
}

func TestHTTPAStreamThatEndsWithoutTheAnswerFailsTheCall(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, _ message) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, ": nothing\n\n")
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)

	_, err := peer.Call(shortContext(t), "ping", nil)
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || !strings.Contains(rpcErr.Message, "ended before the answer") {
		t.Errorf("err = %v", err)
	}
}

func TestHTTPAnUnexpectedContentTypeIsAnError(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, _ message) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html></html>")
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)

	_, err := peer.Call(shortContext(t), "ping", nil)
	if err == nil || !strings.Contains(err.Error(), "unexpected content type") {
		t.Errorf("err = %v", err)
	}
}

func TestHTTPCancelledCallReturnsAtOnceFromASilentServer(t *testing.T) {
	release := make(chan struct{})
	stub := newHTTPStub(t, func(_ http.ResponseWriter, _ *http.Request, _ message) { <-release })
	t.Cleanup(func() { close(release) })
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := peer.Call(ctx, "ping", nil)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 5*time.Second {
		t.Errorf("err = %v after %v", err, time.Since(started))
	}
}

type fixedToken string

func (f fixedToken) Token(context.Context) (string, error) { return string(f), nil }

func TestHTTPTokenSourceAddsABearerTokenThatCustomHeadersOverride(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, msg message) {
		writeJSONResult(w, msg.ID, `{}`)
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL, Tokens: fixedToken("tok")}, nil)
	if _, err := peer.Call(shortContext(t), "ping", nil); err != nil {
		t.Fatal(err)
	}
	if got := stub.seen(http.MethodPost)[0].Header.Get("Authorization"); got != "Bearer tok" {
		t.Errorf("Authorization = %q", got)
	}

	custom := HTTPConfig{URL: stub.URL, Tokens: fixedToken("tok"), Headers: http.Header{"Authorization": {"Basic x"}}}
	peer = newHTTPPeer(t, custom, nil)
	if _, err := peer.Call(shortContext(t), "ping", nil); err != nil {
		t.Fatal(err)
	}
	if got := stub.seen(http.MethodPost)[1].Header.Get("Authorization"); got != "Basic x" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestHTTPRedirectsToAnotherOriginAreNotFollowed(t *testing.T) {
	other := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, msg message) {
		writeJSONResult(w, msg.ID, `{}`)
	})
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, _ message) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL, Headers: http.Header{"X-Api-Key": {"k"}}}, nil)

	_, err := peer.Call(shortContext(t), "ping", nil)
	var status *HTTPStatusError
	if !errors.As(err, &status) || status.Status != http.StatusTemporaryRedirect {
		t.Errorf("err = %v", err)
	}
	if got := len(other.seen(http.MethodPost)); got != 0 {
		t.Errorf("the other origin got %d requests", got)
	}
}

func TestHTTPSameOriginTemporaryRedirectIsFollowedWithTheBody(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, msg message) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", http.StatusTemporaryRedirect)
			return
		}
		writeJSONResult(w, msg.ID, `{"ok":true}`)
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL + "/old"}, nil)

	raw, err := peer.Call(shortContext(t), "ping", nil)
	if err != nil || string(raw) != `{"ok":true}` {
		t.Errorf("raw = %s, err = %v", raw, err)
	}
}

func TestHTTPBatchedAnswersAreAllDelivered(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, msg message) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"jsonrpc":"2.0","method":"notifications/prompts/list_changed"},{"jsonrpc":"2.0","id":`+string(msg.ID)+`,"result":{}}]`)
	})
	pushed := make(chan string, 1)
	handler := ClientHandler{OnNotification: func(method string, _ json.RawMessage) { pushed <- method }}
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, handler)

	if _, err := peer.Call(shortContext(t), "ping", nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pushed:
	case <-time.After(5 * time.Second):
		t.Fatal("the notification of the batch never arrived")
	}
}

func TestHTTPNoStandaloneStreamWhenTheServerAnswers405(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, msg message) {
		switch {
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusMethodNotAllowed)
		case msg.Method == "initialize":
			writeJSONResult(w, msg.ID, initializeResult)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)
	if _, err := Initialize(shortContext(t), peer, Implementation{Name: "test", Version: "0"}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for len(stub.seen(http.MethodGet)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if got := len(stub.seen(http.MethodGet)); got != 1 {
		t.Errorf("GET requests = %d, want 1", got)
	}
	if peer.Closed() {
		t.Error("a 405 on the stream ended the connection")
	}
}
