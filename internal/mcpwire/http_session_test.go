package mcpwire

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// forgetfulServer forgets its first session when a tool list names it. The
// second initialize answers as the test decides.
func forgetfulServer(t *testing.T, secondInitialize func(w http.ResponseWriter, msg message)) (*httpStub, *atomic.Int32) {
	t.Helper()
	var initializes atomic.Int32
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, msg message) {
		switch {
		case msg.Method == "initialize" && initializes.Add(1) == 1:
			w.Header().Set("Mcp-Session-Id", "s1")
			writeJSONResult(w, msg.ID, initializeResult)
		case msg.Method == "initialize":
			w.Header().Set("Mcp-Session-Id", "s2")
			secondInitialize(w, msg)
		case msg.Method == "tools/list" && r.Header.Get("Mcp-Session-Id") == "s1":
			w.WriteHeader(http.StatusNotFound)
		case msg.Method == "tools/list":
			writeJSONResult(w, msg.ID, `{"tools":[]}`)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	})
	return stub, &initializes
}

func TestHTTPALostSessionIsReplacedByRepeatingTheHandshake(t *testing.T) {
	answers := map[string]func(w http.ResponseWriter, msg message){
		"json": func(w http.ResponseWriter, msg message) { writeJSONResult(w, msg.ID, initializeResult) },
		"sse":  func(w http.ResponseWriter, msg message) { writeEventResult(w, msg.ID, initializeResult) },
	}
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			stub, initializes := forgetfulServer(t, answer)
			peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)
			session, err := Initialize(shortContext(t), peer, Implementation{Name: "test", Version: "0"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := session.Call(shortContext(t), "tools/list", nil); err != nil {
				t.Fatalf("the call must survive a lost session: %v", err)
			}
			if got := initializes.Load(); got != 2 {
				t.Fatalf("initialize was sent %d times", got)
			}
			lists := stub.seen(http.MethodPost)
			last := lists[len(lists)-1]
			if last.Body.Method != "tools/list" || last.Header.Get("Mcp-Session-Id") != "s2" {
				t.Fatalf("the retry must use the new session, got %s with %q", last.Body.Method, last.Header.Get("Mcp-Session-Id"))
			}
			if got := len(stub.seen(http.MethodPost)); got < 6 {
				t.Fatalf("the initialized notification must be repeated too, saw %d posts", got)
			}
		})
	}
}

func TestHTTPAHandshakeThatFailsOnReplayExpiresTheSession(t *testing.T) {
	stub, _ := forgetfulServer(t, func(w http.ResponseWriter, _ message) { w.WriteHeader(http.StatusServiceUnavailable) })
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)
	session, err := Initialize(shortContext(t), peer, Implementation{Name: "test", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = session.Call(shortContext(t), "tools/list", nil)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v", err)
	}
}

func TestHTTPASessionLostAgainAfterTheReplayExpiresTheSession(t *testing.T) {
	var initializes atomic.Int32
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, msg message) {
		switch msg.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "s"+string(rune('0'+initializes.Add(1))))
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
		t.Fatalf("err = %v", err)
	}
	if got := initializes.Load(); got != 2 {
		t.Fatalf("the handshake must be repeated once, not %d times", got-1)
	}
}

func TestHTTPALostSessionWithoutAHandshakeExpires(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, msg message) {
		if r.Header.Get("Mcp-Session-Id") != "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Mcp-Session-Id", "lonely")
		writeJSONResult(w, msg.ID, `{}`)
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)
	if _, err := peer.Call(shortContext(t), "ping", nil); err != nil {
		t.Fatal(err)
	}
	_, err := peer.Call(shortContext(t), "ping", nil)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v", err)
	}
}

func TestHTTPAReplayWaitsNoLongerThanTheCaller(t *testing.T) {
	release := make(chan struct{})
	var initializes atomic.Int32
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, msg message) {
		switch {
		case msg.Method == "initialize" && initializes.Add(1) == 1:
			w.Header().Set("Mcp-Session-Id", "s1")
			writeJSONResult(w, msg.ID, initializeResult)
		case msg.Method == "initialize":
			<-release
		case msg.Method == "tools/list":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	})
	t.Cleanup(func() { close(release) })
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)
	session, err := Initialize(shortContext(t), peer, Implementation{Name: "test", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = session.Call(ctx, "tools/list", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a caller that gave up must see its own error, got %v", err)
	}
}

func TestHTTPAResponseThatIsNotJSONFailsARequest(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, _ message) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "this is not json")
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)
	_, err := peer.Call(shortContext(t), "ping", nil)
	if err == nil || !strings.Contains(err.Error(), "the body is not JSON") {
		t.Fatalf("err = %v", err)
	}
}

func TestHTTPTransportWriteRejectsAnInvalidMessage(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, _ message) { w.WriteHeader(http.StatusAccepted) })
	transport := NewHTTPTransport(HTTPConfig{URL: stub.URL})
	defer transport.Close()
	err := transport.Write([]byte("{not json"))
	if err == nil || !strings.HasPrefix(err.Error(), "invalid message: ") {
		t.Fatalf("err = %v", err)
	}
	if got := len(stub.seen(http.MethodPost)); got != 0 {
		t.Fatalf("an invalid message was sent %d times", got)
	}
}

func TestHTTPTransportWriteSendsANotificationAndACancellation(t *testing.T) {
	cancelled := make(chan struct{})
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, msg message) {
		w.WriteHeader(http.StatusAccepted)
		if msg.Method == methodCancelled {
			close(cancelled)
		}
	})
	transport := NewHTTPTransport(HTTPConfig{URL: stub.URL})
	defer transport.Close()

	if err := transport.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}`)); err != nil {
		t.Fatal(err)
	}
	if got := len(stub.seen(http.MethodPost)); got != 1 {
		t.Fatalf("the notification must be sent before Write returns, saw %d", got)
	}
	if err := transport.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("the cancellation never reached the server")
	}
}

func TestHTTPCancellationAfterCloseStartsNothing(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, _ message) { w.WriteHeader(http.StatusAccepted) })
	transport := NewHTTPTransport(HTTPConfig{URL: stub.URL})
	_ = transport.Close()
	if err := transport.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`)); err != nil {
		t.Fatal(err)
	}
	if got := len(stub.seen(http.MethodPost)); got != 0 {
		t.Fatalf("a closed transport sent %d requests", got)
	}
}

func TestHTTPErrorTexts(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{&HTTPStatusError{Status: 502}, "HTTP 502"},
		{&HTTPStatusError{Status: 400, Body: "bad"}, "HTTP 400 Bad Request: bad"},
		{&AuthorizationRequiredError{Challenge: `Bearer realm="x"`}, `authorization required: Bearer realm="x"`},
		{&sessionLostError{id: "s"}, "session expired (HTTP 404)"},
	}
	for _, test := range tests {
		if got := test.err.Error(); got != test.want {
			t.Errorf("got %q, want %q", got, test.want)
		}
	}
	if !IsAuthorizationRequired(&AuthorizationRequiredError{}) || IsAuthorizationRequired(errors.New("x")) {
		t.Error("IsAuthorizationRequired must match only the challenge error")
	}
}

func TestHeaderValuesThatCannotTravelAsTextAreEncoded(t *testing.T) {
	plain := []string{"", "abc", "a b", "with-dash_1"}
	for _, value := range plain {
		if got := encodeHeaderValue(value); got != value {
			t.Errorf("%q was changed to %q", value, got)
		}
	}
	encoded := []string{" lead", "trail ", "\tx", "tab\tinside", "line\nbreak", "café", "\x7f", "=?base64?abc?="}
	for _, value := range encoded {
		got := encodeHeaderValue(value)
		if got == value || !strings.HasPrefix(got, "=?base64?") || !strings.HasSuffix(got, "?=") {
			t.Errorf("%q must be wrapped, got %q", value, got)
		}
	}
}
