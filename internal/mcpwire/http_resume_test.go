package mcpwire

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// idKeeper remembers the id of the last POSTed request, so that a GET handler
// can answer it.
type idKeeper struct {
	mu sync.Mutex
	id json.RawMessage
}

func (k *idKeeper) set(id json.RawMessage) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.id = id
}

func (k *idKeeper) get() json.RawMessage {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.id
}

func TestHTTPAStreamThatEndsEarlyIsResumedWithTheLastEventID(t *testing.T) {
	var ids idKeeper
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, msg message) {
		w.Header().Set("Content-Type", "text/event-stream")
		if r.Method == http.MethodPost {
			ids.set(msg.ID)
			_, _ = io.WriteString(w, "id: 7\nretry: 5\ndata:\n\n")
			return
		}
		_, _ = io.WriteString(w, "id: 8\ndata: {\"jsonrpc\":\"2.0\",\"id\":"+string(ids.get())+",\"result\":{\"ok\":true}}\n\n")
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)

	raw, err := peer.Call(shortContext(t), "ping", nil)
	if err != nil || string(raw) != `{"ok":true}` {
		t.Fatalf("raw = %s, err = %v", raw, err)
	}
	gets := stub.seen(http.MethodGet)
	if len(gets) != 1 || gets[0].Header.Get("Last-Event-Id") != "7" {
		t.Errorf("GET requests = %+v", gets)
	}
	if got := gets[0].Header.Get("Accept"); got != "text/event-stream" {
		t.Errorf("Accept = %q", got)
	}
}

func TestHTTPAResumedStreamKeepsTheProtocolHeaders(t *testing.T) {
	var ids idKeeper
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, msg message) {
		switch {
		case msg.Method == "initialize":
			w.Header().Set("Mcp-Session-Id", "abc")
			writeJSONResult(w, msg.ID, initializeResult)
		case msg.kind() == kindNotification:
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPost:
			ids.set(msg.ID)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "id: 1\nretry: 5\ndata:\n\n")
		case len(ids.get()) == 0:
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":"+string(ids.get())+",\"result\":{}}\n\n")
		}
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)
	session, err := Initialize(shortContext(t), peer, Implementation{Name: "test", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := session.Call(shortContext(t), "tools/list", nil); err != nil {
		t.Fatal(err)
	}
	var resumed seenRequest
	for _, get := range stub.seen(http.MethodGet) {
		if get.Header.Get("Last-Event-Id") != "" {
			resumed = get
		}
	}
	if resumed.Header.Get("Mcp-Session-Id") != "abc" || resumed.Header.Get("Mcp-Protocol-Version") != "2025-11-25" {
		t.Errorf("resume headers = %v", resumed.Header)
	}
}

func TestHTTPAnAnswerStreamThatCannotBeResumedFailsTheCall(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, _ message) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "id: 1\nretry: 1\ndata:\n\n")
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)

	_, err := peer.Call(shortContext(t), "ping", nil)
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || !strings.Contains(rpcErr.Message, "ended before the answer") {
		t.Errorf("err = %v", err)
	}
	if got := len(stub.seen(http.MethodGet)); got != maxStreamFailures {
		t.Errorf("GET requests = %d, want %d", got, maxStreamFailures)
	}
}

func TestHTTPAnAnswerStreamIsNotResumedWhenTheServerHasNoStream(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, _ message) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "id: 1\nretry: 1\ndata:\n\n")
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)

	_, err := peer.Call(shortContext(t), "ping", nil)
	if err == nil || !strings.Contains(err.Error(), "ended before the answer") {
		t.Errorf("err = %v", err)
	}
	if got := len(stub.seen(http.MethodGet)); got != 1 {
		t.Errorf("GET requests = %d, want 1", got)
	}
}

func TestHTTPAForgottenSessionIsReopenedAndTheCallRepeatedOnce(t *testing.T) {
	var initializes atomic.Int32
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, msg message) {
		session := r.Header.Get("Mcp-Session-Id")
		switch {
		case r.Method != http.MethodPost:
			w.WriteHeader(http.StatusMethodNotAllowed)
		case msg.Method == "initialize":
			w.Header().Set("Mcp-Session-Id", "s"+string(rune('0'+initializes.Add(1))))
			writeJSONResult(w, msg.ID, initializeResult)
		case msg.kind() == kindNotification:
			w.WriteHeader(http.StatusAccepted)
		case session == "s1":
			w.WriteHeader(http.StatusNotFound)
		default:
			writeJSONResult(w, msg.ID, `{"session":"`+session+`"}`)
		}
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)
	session, err := Initialize(shortContext(t), peer, Implementation{Name: "test", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := session.Call(shortContext(t), "tools/list", nil)
	if err != nil || string(raw) != `{"session":"s2"}` {
		t.Fatalf("raw = %s, err = %v", raw, err)
	}
	if peer.Closed() {
		t.Error("the connection ended")
	}
	if got := initializes.Load(); got != 2 {
		t.Errorf("initialize requests = %d, want 2", got)
	}
	initialized := 0
	for _, post := range stub.seen(http.MethodPost) {
		if post.Body.Method == "notifications/initialized" {
			initialized++
		}
	}
	if initialized != 2 {
		t.Errorf("initialized notifications = %d, want 2", initialized)
	}
}

func TestHTTPASessionLostAgainEndsTheConnection(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, msg message) {
		switch {
		case r.Method != http.MethodPost:
			w.WriteHeader(http.StatusMethodNotAllowed)
		case msg.Method == "initialize":
			w.Header().Set("Mcp-Session-Id", "abc")
			writeJSONResult(w, msg.ID, initializeResult)
		case msg.kind() == kindNotification:
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)
	session, err := Initialize(shortContext(t), peer, Implementation{Name: "test", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := session.Call(shortContext(t), "tools/list", nil); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("err = %v", err)
	}
	var tries int
	for _, post := range stub.seen(http.MethodPost) {
		if post.Body.Method == "tools/list" {
			tries++
		}
	}
	if tries != 2 {
		t.Errorf("tools/list requests = %d, want 2", tries)
	}
}

func TestHTTPForbiddenWithAChallengeAsksForAuthorization(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, _ message) {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="files:write"`)
		w.WriteHeader(http.StatusForbidden)
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)

	_, err := peer.Call(shortContext(t), "ping", nil)
	var required *AuthorizationRequiredError
	if !errors.As(err, &required) || !strings.Contains(required.Challenge, "files:write") {
		t.Errorf("err = %v", err)
	}
}

func TestHTTPForbiddenWithoutAChallengeIsAnHTTPError(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, _ *http.Request, _ message) {
		w.WriteHeader(http.StatusForbidden)
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)

	_, err := peer.Call(shortContext(t), "ping", nil)
	var status *HTTPStatusError
	if !errors.As(err, &status) || status.Status != http.StatusForbidden || IsAuthorizationRequired(err) {
		t.Errorf("err = %v", err)
	}
}

func TestHTTPStandaloneStreamEndsTheConnectionWhenTheSessionIsGone(t *testing.T) {
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, msg message) {
		switch {
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case msg.Method == "initialize":
			w.Header().Set("Mcp-Session-Id", "abc")
			writeJSONResult(w, msg.ID, initializeResult)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	})
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, nil)
	if _, err := Initialize(shortContext(t), peer, Implementation{Name: "test", Version: "0"}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-peer.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the peer stayed open")
	}
}

func TestHTTPStandaloneStreamRetriesAfterAServerError(t *testing.T) {
	var gets atomic.Int32
	pushed := make(chan string, 1)
	stub := newHTTPStub(t, func(w http.ResponseWriter, r *http.Request, msg message) {
		switch {
		case r.Method == http.MethodGet && gets.Add(1) == 1:
			w.WriteHeader(http.StatusBadGateway)
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case msg.Method == "initialize":
			writeJSONResult(w, msg.ID, initializeResult)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	})
	handler := ClientHandler{OnNotification: func(method string, _ json.RawMessage) { pushed <- method }}
	peer := newHTTPPeer(t, HTTPConfig{URL: stub.URL}, handler)
	if _, err := Initialize(shortContext(t), peer, Implementation{Name: "test", Version: "0"}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-pushed:
	case <-time.After(10 * time.Second):
		t.Fatal("the stream was never opened again")
	}
}

func TestHTTPNothingRunsInTheBackgroundOnceClosed(t *testing.T) {
	transport := NewHTTPTransport(HTTPConfig{URL: "http://127.0.0.1:1"})
	if !transport.runInBackground(func() {}) {
		t.Error("the work was refused by an open transport")
	}
	_ = transport.Close()
	if transport.runInBackground(func() { t.Error("ran after Close") }) {
		t.Error("the work was started by a closed transport")
	}
}
