package mcpwire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	maxJSONResponse  = 16 * 1024 * 1024
	maxErrorResponse = 64 * 1024
	maxRedirects     = 10
	// notifyTimeout bounds a message that expects no answer, so that a silent
	// server cannot hold up the sender.
	notifyTimeout = 30 * time.Second
	closeTimeout  = 5 * time.Second
	// maxStreamFailures is how many times in a row the standalone stream may
	// fail to open before it is given up.
	maxStreamFailures  = 3
	defaultStreamRetry = time.Second
)

// TokenSource gives the access token to send with each request.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// HTTPConfig describes a streamable HTTP endpoint.
type HTTPConfig struct {
	URL string
	// Headers are sent with every request. They may hold secrets, so the
	// transport puts none of them in an error.
	Headers http.Header
	// Client is the HTTP client. Nil gives one that follows only same-origin
	// 307 and 308 redirects, so that headers never reach another origin.
	Client *http.Client
	// Tokens adds a bearer token when it is not nil.
	Tokens TokenSource
}

// HTTPTransport is the client side of MCP over streamable HTTP. Each message
// is a POST. The answer comes as a JSON body or as a stream of events, and
// both end up in Read.
type HTTPTransport struct {
	config HTTPConfig
	client *http.Client
	queue  *messageQueue

	ctx    context.Context
	cancel context.CancelFunc

	mu           sync.Mutex
	closed       bool
	background   sync.WaitGroup
	sessionID    string
	version      string
	initializeID string
	// initializeBody and initializedBody are the handshake messages, kept to
	// open a new session when the server forgets the old one.
	initializeBody  []byte
	initializedBody []byte

	// reinit lets one call at a time open the new session.
	reinit sync.Mutex
}

// NewHTTPTransport returns a transport that has not sent anything yet.
func NewHTTPTransport(config HTTPConfig) *HTTPTransport {
	client := config.Client
	if client == nil {
		client = &http.Client{CheckRedirect: sameOriginRedirect}
	}
	t := &HTTPTransport{config: config, client: client, queue: newMessageQueue()}
	t.ctx, t.cancel = context.WithCancel(context.Background())
	return t
}

// sameOriginRedirect follows 307 and 308 only, and only within the origin,
// because the custom headers hold credentials. Other redirects come back as
// the failed answer.
func sameOriginRedirect(req *http.Request, via []*http.Request) error {
	status := req.Response.StatusCode
	sameOrigin := req.URL.Scheme == via[0].URL.Scheme && req.URL.Host == via[0].URL.Host
	if len(via) > maxRedirects || !sameOrigin || (status != http.StatusTemporaryRedirect && status != http.StatusPermanentRedirect) {
		return http.ErrUseLastResponse
	}
	return nil
}

// Read waits for the next message from the server.
func (t *HTTPTransport) Read() ([]byte, error) {
	return t.queue.pop()
}

// Write sends a message that is not tied to any caller.
func (t *HTTPTransport) Write(message []byte) error {
	return t.WriteContext(context.Background(), message)
}

// WriteContext sends a message and returns once the server has accepted it.
// A failed request is an error here and never reaches Read. Over a stream of
// events the answer may arrive later.
func (t *HTTPTransport) WriteContext(ctx context.Context, raw []byte) error {
	msg, err := decodeMessage(raw)
	if err != nil {
		return fmt.Errorf("invalid message: %w", err)
	}
	if msg.kind() == kindRequest {
		return t.post(ctx, raw, msg)
	}
	if msg.Method == methodCancelled {
		return t.postInBackground(raw, msg)
	}
	return t.postBounded(ctx, raw, msg)
}

func (t *HTTPTransport) postBounded(ctx context.Context, raw []byte, msg message) error {
	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	return t.post(ctx, raw, msg)
}

// postInBackground sends a cancellation without waiting: it is sent because
// the server did not answer, so it may not answer this either.
func (t *HTTPTransport) postInBackground(raw []byte, msg message) error {
	t.runInBackground(func() { _ = t.postBounded(context.Background(), raw, msg) })
	return nil
}

// runInBackground reports whether the work was started. It is not once the
// transport is closed.
func (t *HTTPTransport) runInBackground(work func()) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.background.Go(work)
	return true
}

// requestContext ends when ctx ends or the transport is closed.
func (t *HTTPTransport) requestContext(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(t.ctx, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

func (t *HTTPTransport) post(ctx context.Context, raw []byte, msg message) error {
	t.rememberHandshake(raw, msg)
	err := t.postOnce(ctx, raw, msg)
	var lost *sessionLostError
	if errors.As(err, &lost) {
		err = t.retryAfterReinitialize(ctx, raw, msg, lost.id)
	}
	if err != nil {
		return err
	}
	if msg.Method == methodInitialized {
		t.listenForServerMessages()
	}
	return nil
}

func (t *HTTPTransport) postOnce(ctx context.Context, raw []byte, msg message) error {
	ctx, release := t.requestContext(ctx)
	request, err := t.newRequest(ctx, http.MethodPost, bytes.NewReader(raw))
	if err != nil {
		release()
		return err
	}
	setProtocolHeaders(request.Header, msg, t.negotiatedVersion())
	t.expectInitializeAnswer(msg)
	response, err := t.client.Do(request)
	if err != nil {
		release()
		return err
	}
	return t.handleResponse(response, msg, release)
}

func (t *HTTPTransport) newRequest(ctx context.Context, method string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, t.config.URL, body)
	if err != nil {
		return nil, err
	}
	setContentHeaders(request)
	if err := t.setToken(ctx, request); err != nil {
		return nil, err
	}
	for name, values := range t.config.Headers {
		request.Header[http.CanonicalHeaderKey(name)] = slices.Clone(values)
	}
	if id := t.session(); id != "" {
		request.Header.Set(headerSessionID, id)
	}
	return request, nil
}

func setContentHeaders(request *http.Request) {
	switch request.Method {
	case http.MethodPost:
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
	case http.MethodGet:
		request.Header.Set("Accept", "text/event-stream")
	}
}

func (t *HTTPTransport) setToken(ctx context.Context, request *http.Request) error {
	if t.config.Tokens == nil {
		return nil
	}
	token, err := t.config.Tokens.Token(ctx)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (t *HTTPTransport) session() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sessionID
}

func (t *HTTPTransport) negotiatedVersion() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.version
}

// expectInitializeAnswer remembers the id of an initialize request, to learn
// the agreed version from its answer.
func (t *HTTPTransport) expectInitializeAnswer(msg message) {
	if msg.Method != methodInitialize || msg.kind() != kindRequest {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.initializeID = idKey(msg.ID)
}

// handleResponse takes over the response. It reads the body, or leaves a
// stream of events to a goroutine that releases the request when it is done.
func (t *HTTPTransport) handleResponse(response *http.Response, sent message, release func()) error {
	streaming := false
	defer func() {
		if !streaming {
			_ = response.Body.Close()
			release()
		}
	}()
	err := t.checkStatus(response, sent)
	if errors.Is(err, errErrorDelivered) {
		return nil
	}
	if err != nil || isAccepted(response, sent) {
		return err
	}
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	switch mediaType {
	case "application/json":
		return t.deliverJSON(response.Body, sent)
	case "text/event-stream":
		streaming = true
		started := t.runInBackground(func() { t.pumpResponseStream(response, sent, release) })
		if !started {
			streaming = false
		}
		return nil
	}
	return fmt.Errorf("unexpected content type: %q", response.Header.Get("Content-Type"))
}

// isAccepted covers 202 and 204, and an empty 200 for a message that expects
// no answer, which some servers send.
func isAccepted(response *http.Response, sent message) bool {
	switch response.StatusCode {
	case http.StatusAccepted, http.StatusNoContent:
		return true
	}
	return response.ContentLength == 0 && sent.kind() != kindRequest
}

// errErrorDelivered says that the JSON-RPC error in a failed response was
// queued for Read, so nothing more is left to do with the response.
var errErrorDelivered = errors.New("the JSON-RPC error was delivered")

// checkStatus returns the error of a failed request. A JSON-RPC error in the
// body of the answer to a request is not a failure: it goes to Read.
func (t *HTTPTransport) checkStatus(response *http.Response, sent message) error {
	status := response.StatusCode
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		if challenge := response.Header.Get("WWW-Authenticate"); challenge != "" {
			return &AuthorizationRequiredError{Challenge: challenge}
		}
	}
	if status >= 200 && status < 300 {
		t.rememberSession(response.Header)
		return nil
	}
	if id := response.Request.Header.Get(headerSessionID); status == http.StatusNotFound && id != "" {
		return &sessionLostError{id: id}
	}
	return t.failedStatus(response, sent)
}

func (t *HTTPTransport) rememberSession(header http.Header) {
	id := header.Get(headerSessionID)
	if id == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sessionID == "" {
		t.sessionID = id
	}
}

// expireSession ends the connection, because no later request can succeed.
func (t *HTTPTransport) expireSession() error {
	t.mu.Lock()
	t.sessionID = ""
	t.mu.Unlock()
	t.queue.close(ErrSessionExpired)
	return ErrSessionExpired
}

func (t *HTTPTransport) failedStatus(response *http.Response, sent message) error {
	status := response.StatusCode
	bodyFree := status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
	isAuth := status == http.StatusUnauthorized || status == http.StatusForbidden
	isJSON := hasMediaType(response, "application/json")
	if bodyFree && !isJSON {
		return &HTTPStatusError{Status: status}
	}
	body, err := readLimited(response.Body, maxErrorResponse)
	if err != nil {
		body = nil
	}
	if isJSON && !isAuth && t.forwardJSONRPCError(body, sent) {
		return errErrorDelivered
	}
	if bodyFree {
		return &HTTPStatusError{Status: status}
	}
	return &HTTPStatusError{Status: status, Body: strings.ToValidUTF8(strings.TrimSpace(string(body)), "�")}
}

func hasMediaType(response *http.Response, want string) bool {
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	return mediaType == want
}

// forwardJSONRPCError passes on an error body that answers the request. An
// answer with another id could never reach its caller, which would wait for
// ever.
func (t *HTTPTransport) forwardJSONRPCError(body []byte, sent message) bool {
	msg, err := decodeMessage(body)
	if err != nil || sent.kind() != kindRequest {
		return false
	}
	if msg.Error == nil || !msg.hasID() || idKey(msg.ID) != idKey(sent.ID) {
		return false
	}
	t.queue.push(body)
	return true
}

func readLimited(r io.Reader, limit int) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, fmt.Errorf("HTTP response body exceeded the maximum size of %d bytes", limit)
	}
	return body, nil
}

// deliverJSON queues the message, or the messages of a batch, in the body.
func (t *HTTPTransport) deliverJSON(body io.Reader, sent message) error {
	data, err := readLimited(body, maxJSONResponse)
	if err != nil {
		return err
	}
	messages := splitMessages(data)
	if messages == nil && sent.kind() == kindRequest {
		return errors.New("unexpected server response: the body is not JSON")
	}
	for _, raw := range messages {
		t.receive(raw)
	}
	return nil
}

// splitMessages returns the messages of a body. It is nil when the body is not
// JSON.
func splitMessages(body []byte) [][]byte {
	body = bytes.TrimSpace(body)
	if !json.Valid(body) {
		return nil
	}
	if !bytes.HasPrefix(body, []byte("[")) {
		return [][]byte{body}
	}
	var batch []json.RawMessage
	if json.Unmarshal(body, &batch) != nil {
		return nil
	}
	messages := make([][]byte, 0, len(batch))
	for _, raw := range batch {
		messages = append(messages, raw)
	}
	return messages
}

// receive queues a message from the server.
func (t *HTTPTransport) receive(raw []byte) message {
	msg, err := decodeMessage(raw)
	if err != nil {
		return message{}
	}
	if msg.kind() == kindResponse {
		t.learnVersion(msg)
	}
	t.queue.push(raw)
	return msg
}

// learnVersion takes the version from the answer to initialize. Later requests
// must name it in a header.
func (t *HTTPTransport) learnVersion(msg message) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.initializeID == "" || idKey(msg.ID) != t.initializeID {
		return
	}
	t.initializeID = ""
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if msg.Error == nil && json.Unmarshal(msg.Result, &result) == nil {
		t.version = result.ProtocolVersion
	}
}

func streamEndedError(id json.RawMessage, cause error) []byte {
	text := "the response stream ended before the answer"
	if cause != nil {
		text += ": " + cause.Error()
	}
	data, _ := encodeError(id, InternalError(text))
	return data
}

// receiveEvent queues the message of an event. Events of another type, and
// events without data, carry no message.
func (t *HTTPTransport) receiveEvent(event sseEvent) message {
	if (event.Type != "" && event.Type != "message") || event.Data == "" {
		return message{}
	}
	return t.receive([]byte(event.Data))
}

// listenForServerMessages opens the standalone stream of 2025-11-25, over
// which the server may send requests and notifications by itself. Later
// versions have no such stream.
func (t *HTTPTransport) listenForServerMessages() {
	version := t.negotiatedVersion()
	if version == "" || !hasInitialize(version) {
		return
	}
	t.runInBackground(t.listen)
}

// Close ends the session, when the server has one, and stops every request
// still running.
func (t *HTTPTransport) Close() error {
	t.mu.Lock()
	alreadyClosed := t.closed
	t.closed = true
	t.mu.Unlock()
	if alreadyClosed {
		return nil
	}
	t.queue.close(nil)
	t.endSession()
	t.cancel()
	t.background.Wait()
	return nil
}

// endSession tells the server that the session is over. A server that does
// not support this answers 405, which is fine.
func (t *HTTPTransport) endSession() {
	if t.session() == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
	defer cancel()
	request, err := t.newRequest(ctx, http.MethodDelete, nil)
	if err != nil {
		return
	}
	if version := t.negotiatedVersion(); version != "" {
		request.Header.Set(headerProtocolVersion, version)
	}
	response, err := t.client.Do(request)
	if err != nil {
		return
	}
	_ = response.Body.Close()
}
