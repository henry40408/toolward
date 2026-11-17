package mcpwire

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const inlineMetaJSON = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`

// serverClient is a plain peer talking to a Server.
func serverClient(t *testing.T, onInitialized func(*Peer)) *Peer {
	t.Helper()
	client, _ := connect(t, nil, NewServer(testServerConfig(onInitialized)))
	return client
}

func callError(t *testing.T, client *Peer, method, params string) *Error {
	t.Helper()
	_, err := client.Call(testContext(t), method, json.RawMessage(params))
	var rpcErr *Error
	if !errors.As(err, &rpcErr) {
		t.Fatalf("%s: err = %v, want a JSON-RPC error", method, err)
	}
	return rpcErr
}

func TestServerAnswersPingBeforeAnyLifecycle(t *testing.T) {
	client := serverClient(t, nil)
	if _, err := client.Call(testContext(t), "ping", nil); err != nil {
		t.Fatal(err)
	}
}

func TestServerInitializeNegotiatesTheVersion(t *testing.T) {
	cases := map[string]string{
		"2024-11-05": "2024-11-05",
		"2025-06-18": "2025-06-18",
		"2025-11-25": "2025-11-25",
		"2026-07-28": "2025-11-25",
		"1999-01-01": "2025-11-25",
	}
	for requested, want := range cases {
		t.Run(requested, func(t *testing.T) {
			client := serverClient(t, nil)
			raw, err := client.Call(testContext(t), "initialize", json.RawMessage(`{"protocolVersion":"`+requested+`","capabilities":{},"clientInfo":{"name":"c","version":"1"}}`))
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				ProtocolVersion string         `json:"protocolVersion"`
				ServerInfo      Implementation `json:"serverInfo"`
			}
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			if result.ProtocolVersion != want || result.ServerInfo.Name != "toolward" {
				t.Errorf("result = %s, want version %s", raw, want)
			}
		})
	}
}

func TestServerInitializeRejectsMissingVersion(t *testing.T) {
	client := serverClient(t, nil)
	if err := callError(t, client, "initialize", `{}`); err.Code != CodeInvalidParams {
		t.Errorf("code = %d", err.Code)
	}
}

func TestServerCallsOnInitializedAfterTheNotification(t *testing.T) {
	got := make(chan *Peer, 1)
	client := serverClient(t, func(peer *Peer) { got <- peer })
	if _, err := Initialize(testContext(t), client, Implementation{Name: "c", Version: "1"}); err != nil {
		t.Fatal(err)
	}
	select {
	case peer := <-got:
		if peer == nil {
			t.Error("OnInitialized got no peer")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnInitialized was not called")
	}
}

func TestServerDoesNotCallOnInitializedForStatelessClients(t *testing.T) {
	called := make(chan struct{}, 1)
	client := serverClient(t, func(*Peer) { called <- struct{}{} })
	if _, err := Discover(testContext(t), client, Implementation{Name: "c", Version: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := client.Notify(methodInitialized, nil); err != nil {
		t.Fatal(err)
	}
	// A request after the notification proves it was handled.
	if _, err := client.Call(testContext(t), "tools/list", json.RawMessage(`{`+inlineMetaJSON+`}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
		t.Error("OnInitialized was called")
	default:
	}
}

func TestServerDiscoverResult(t *testing.T) {
	client := serverClient(t, nil)
	raw, err := client.Call(testContext(t), "server/discover", json.RawMessage(`{`+inlineMetaJSON+`}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"resultType":"complete","supportedVersions":["2024-11-05","2025-03-26","2025-06-18","2025-11-25","2026-07-28"],` +
		`"capabilities":{"tools":{"listChanged":true}},"ttlMs":0,"cacheScope":"private",` +
		`"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"toolward","version":"test"}}}`
	if string(raw) != want {
		t.Errorf("discover result:\n got %s\nwant %s", raw, want)
	}
}

func TestServerDiscoverNeedsInlineMeta(t *testing.T) {
	client := serverClient(t, nil)
	err := callError(t, client, "server/discover", `{}`)
	want := "request _meta is missing or has malformed required fields: " +
		"io.modelcontextprotocol/protocolVersion, io.modelcontextprotocol/clientCapabilities"
	if err.Code != CodeInvalidParams || err.Message != want {
		t.Errorf("error = %+v", err)
	}
}

func TestServerNamesOnlyTheMissingKey(t *testing.T) {
	client := serverClient(t, nil)
	err := callError(t, client, "tools/list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`)
	want := "request _meta is missing or has malformed required fields: io.modelcontextprotocol/clientCapabilities"
	if err.Message != want {
		t.Errorf("message = %q", err.Message)
	}
}

func TestServerTreatsMalformedMetaAsMissing(t *testing.T) {
	client := serverClient(t, nil)
	err := callError(t, client, "tools/list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":5,"io.modelcontextprotocol/clientCapabilities":"x"}}`)
	if !strings.HasSuffix(err.Message, "protocolVersion, io.modelcontextprotocol/clientCapabilities") {
		t.Errorf("message = %q", err.Message)
	}
}

func TestServerRejectsAnUnknownInlineVersion(t *testing.T) {
	client := serverClient(t, nil)
	err := callError(t, client, "tools/list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}`)
	if err.Code != CodeUnsupportedProtocolVersion || err.Message != "Unsupported protocol version" {
		t.Fatalf("error = %+v", err)
	}
	want := `{"requested":"2099-01-01","supported":["2024-11-05","2025-03-26","2025-06-18","2025-11-25","2026-07-28"]}`
	if string(err.Data) != want {
		t.Errorf("data = %s", err.Data)
	}
	// The refusal does not pick a lifecycle: a handshake still works.
	if _, err := Initialize(testContext(t), client, Implementation{Name: "c", Version: "1"}); err != nil {
		t.Errorf("initialize after the refusal: %v", err)
	}
}

func TestServerWithoutMetaAndWithoutInitializeRefusesRequests(t *testing.T) {
	client := serverClient(t, nil)
	if err := callError(t, client, "tools/list", `{}`); err.Code != CodeInvalidParams {
		t.Errorf("code = %d", err.Code)
	}
}

func TestStatelessConnectionRefusesPing(t *testing.T) {
	client := serverClient(t, nil)
	if _, err := client.Call(testContext(t), "tools/list", json.RawMessage(`{`+inlineMetaJSON+`}`)); err != nil {
		t.Fatal(err)
	}
	err := callError(t, client, "ping", `{`+inlineMetaJSON+`}`)
	if err.Code != CodeMethodNotFound || err.Message != "ping" {
		t.Errorf("error = %+v", err)
	}
	// Once inline, a request must keep carrying its meta.
	if err := callError(t, client, "tools/list", `{}`); err.Code != CodeInvalidParams {
		t.Errorf("code = %d", err.Code)
	}
}

func TestHandshakeConnectionAnswersPingAndNeedsNoMeta(t *testing.T) {
	client := serverClient(t, nil)
	if _, err := Initialize(testContext(t), client, Implementation{Name: "c", Version: "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Call(testContext(t), "ping", nil); err != nil {
		t.Errorf("ping: %v", err)
	}
	if _, err := client.Call(testContext(t), "tools/list", nil); err != nil {
		t.Errorf("tools/list: %v", err)
	}
}

func TestHandshakeConnectionHoldsInlineRequestsToTheirMeta(t *testing.T) {
	client := serverClient(t, nil)
	if _, err := Initialize(testContext(t), client, Implementation{Name: "c", Version: "1"}); err != nil {
		t.Fatal(err)
	}
	err := callError(t, client, "ping", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`)
	if err.Code != CodeInvalidParams {
		t.Errorf("error = %+v", err)
	}
	if err := callError(t, client, "server/discover", `{}`); err.Code != CodeInvalidParams {
		t.Errorf("discover without meta: %+v", err)
	}
}

func TestServerUnknownMethodsAndCompletion(t *testing.T) {
	client := serverClient(t, nil)
	if _, err := Initialize(testContext(t), client, Implementation{Name: "c", Version: "1"}); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"resources/subscribe", "logging/setLevel", "tasks/get", "bogus"} {
		if err := callError(t, client, method, `{}`); err.Code != CodeMethodNotFound || err.Message != method {
			t.Errorf("%s: %+v", method, err)
		}
	}
	raw, err := client.Call(testContext(t), "completion/complete", json.RawMessage(`{}`))
	if err != nil || string(raw) != `{"completion":{"values":[]}}` {
		t.Errorf("completion = %s, %v", raw, err)
	}
}

// stubHandler answers every request with a fixed reply.
func stubServer(t *testing.T, reply func(call int) (json.RawMessage, error)) (*Peer, *[]json.RawMessage) {
	t.Helper()
	var seen []json.RawMessage
	handler := funcHandler{request: func(_ context.Context, _ string, params json.RawMessage) (json.RawMessage, error) {
		seen = append(seen, params)
		return reply(len(seen))
	}}
	client, _ := connect(t, nil, handler)
	return client, &seen
}

func TestSessionAddsInlineMetaAndKeepsOtherMeta(t *testing.T) {
	client := serverClient(t, nil)
	session, err := Discover(testContext(t), client, Implementation{Name: "c", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if session.Info.ProtocolVersion != Version20260728 || session.Info.ServerInfo.Name != "toolward" {
		t.Errorf("info = %+v", session.Info)
	}
	if string(session.Info.Capabilities) != `{"tools":{"listChanged":true}}` {
		t.Errorf("capabilities = %s", session.Info.Capabilities)
	}

	seen := make(chan json.RawMessage, 1)
	capture := funcHandler{request: func(_ context.Context, _ string, params json.RawMessage) (json.RawMessage, error) {
		seen <- params
		return nil, nil
	}}
	other, _ := connect(t, nil, capture)
	stateless := &Session{Peer: other, inlineMeta: session.inlineMeta}
	if _, err := stateless.Call(testContext(t), "tools/call", json.RawMessage(`{"name":"x","_meta":{"progressToken":"p"}}`)); err != nil {
		t.Fatal(err)
	}
	want := `{"_meta":{"io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"c","version":"1"},` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28","progressToken":"p"},"name":"x"}`
	if got := string(<-seen); got != want {
		t.Errorf("params:\n got %s\nwant %s", got, want)
	}
}

func TestSessionAfterInitializeSendsParamsUntouched(t *testing.T) {
	seen := make(chan json.RawMessage, 1)
	capture := funcHandler{request: func(_ context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
		if method == "initialize" {
			return json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"s","version":"1"}}`), nil
		}
		seen <- params
		return nil, nil
	}}
	client, _ := connect(t, nil, capture)
	session, err := Initialize(testContext(t), client, Implementation{Name: "c", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Call(testContext(t), "tools/list", json.RawMessage(`{"cursor":"z"}`)); err != nil {
		t.Fatal(err)
	}
	if got := string(<-seen); got != `{"cursor":"z"}` {
		t.Errorf("params = %s", got)
	}
}

func TestInitializeWithAVersionWithoutHandshakeSwitchesToInlineMeta(t *testing.T) {
	seen := make(chan json.RawMessage, 1)
	capture := funcHandler{request: func(_ context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
		if method == "initialize" {
			return json.RawMessage(`{"protocolVersion":"2026-07-28","capabilities":{},"serverInfo":{"name":"s","version":"1"}}`), nil
		}
		seen <- params
		return nil, nil
	}}
	client, _ := connect(t, nil, capture)
	session, err := Initialize(testContext(t), client, Implementation{Name: "c", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Call(testContext(t), "tools/list", nil); err != nil {
		t.Fatal(err)
	}
	if got := string(<-seen); !strings.Contains(got, `"io.modelcontextprotocol/protocolVersion":"2026-07-28"`) {
		t.Errorf("params = %s", got)
	}
}

func TestDiscoverFailureOfAnOlderServerIsAnRPCError(t *testing.T) {
	client, _ := stubServer(t, func(int) (json.RawMessage, error) { return nil, MethodNotFound("server/discover") })
	_, err := Discover(testContext(t), client, Implementation{Name: "c", Version: "1"})
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != CodeMethodNotFound {
		t.Fatalf("err = %v", err)
	}
	if IsModernRejection(err) {
		t.Error("an older server is not a modern rejection")
	}
	if !strings.HasPrefix(err.Error(), "JSON-RPC error: -32601: ") {
		t.Errorf("text = %q", err.Error())
	}
}

func TestIsModernRejection(t *testing.T) {
	for _, code := range []int{CodeMissingRequiredClientCapability, CodeHeaderMismatch, CodeUnsupportedProtocolVersion} {
		if !IsModernRejection(NewError(code, "x")) {
			t.Errorf("code %d should be a modern rejection", code)
		}
	}
	if IsModernRejection(NewError(CodeInternalError, "x")) || IsModernRejection(errors.New("x")) {
		t.Error("other errors are not modern rejections")
	}
}

func unsupportedVersionError() error {
	return &Error{
		Code:    CodeUnsupportedProtocolVersion,
		Message: "Unsupported protocol version",
		Data:    json.RawMessage(`{"supported":["2026-07-28"]}`),
	}
}

func TestDiscoverRetriesTheSameVersionOnce(t *testing.T) {
	client, seen := stubServer(t, func(call int) (json.RawMessage, error) {
		if call == 1 {
			return nil, unsupportedVersionError()
		}
		return json.RawMessage(`{"supportedVersions":["2026-07-28"],"capabilities":{}}`), nil
	})
	if _, err := Discover(testContext(t), client, Implementation{Name: "c", Version: "1"}); err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 2 {
		t.Errorf("discover requests = %d, want 2", len(*seen))
	}
}

func TestDiscoverGivesUpAfterTheRetry(t *testing.T) {
	client, seen := stubServer(t, func(int) (json.RawMessage, error) { return nil, unsupportedVersionError() })
	_, err := Discover(testContext(t), client, Implementation{Name: "c", Version: "1"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(*seen) != 2 {
		t.Errorf("discover requests = %d, want 2", len(*seen))
	}
}

func TestDiscoverFailsWhenNoVersionIsShared(t *testing.T) {
	client, _ := stubServer(t, func(int) (json.RawMessage, error) {
		return json.RawMessage(`{"supportedVersions":["2025-11-25"],"capabilities":{}}`), nil
	})
	_, err := Discover(testContext(t), client, Implementation{Name: "c", Version: "1"})
	if err == nil || !strings.Contains(err.Error(), "no compatible protocol version") {
		t.Errorf("err = %v", err)
	}
}

func TestInitializeRefusesAnUnreadableResult(t *testing.T) {
	client, _ := stubServer(t, func(int) (json.RawMessage, error) { return json.RawMessage(`{}`), nil })
	_, err := Initialize(testContext(t), client, Implementation{Name: "c", Version: "1"})
	if err == nil || !strings.HasPrefix(err.Error(), "expect initialized result, but received: ") {
		t.Errorf("err = %v", err)
	}
}
