package mcpwire

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
)

// sessionLostError says that the server answered 404 to a request that named a
// session. It is internal: post turns it into a retry or ErrSessionExpired.
type sessionLostError struct {
	id string
}

func (e *sessionLostError) Error() string { return ErrSessionExpired.Error() }

var (
	errNoHandshake = errors.New("no handshake to repeat")
	errAnswerSeen  = errors.New("the answer was seen")
)

// rememberHandshake keeps the messages that open a session.
func (t *HTTPTransport) rememberHandshake(raw []byte, msg message) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case msg.Method == methodInitialize && msg.kind() == kindRequest:
		t.initializeBody = slices.Clone(raw)
		t.initializedBody = nil
	case msg.Method == methodInitialized:
		t.initializedBody = slices.Clone(raw)
	}
}

func (t *HTTPTransport) handshake() (initialize, initialized []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.initializeBody, t.initializedBody
}

func (t *HTTPTransport) setSession(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessionID = id
}

// retryAfterReinitialize opens a new session and sends the message again, once.
// A session that is lost a second time ends the connection.
func (t *HTTPTransport) retryAfterReinitialize(ctx context.Context, raw []byte, msg message, lostID string) error {
	if err := t.reinitialize(ctx, lostID); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return t.expireSession()
	}
	err := t.postOnce(ctx, raw, msg)
	var lost *sessionLostError
	if errors.As(err, &lost) {
		return t.expireSession()
	}
	return err
}

// reinitialize repeats the handshake. Calls that lost the same session wait for
// the first one, and find the new session in place.
func (t *HTTPTransport) reinitialize(ctx context.Context, lostID string) error {
	t.reinit.Lock()
	defer t.reinit.Unlock()
	if t.session() != lostID {
		return nil
	}
	initialize, initialized := t.handshake()
	if initialize == nil {
		return errNoHandshake
	}
	t.setSession("")
	if err := t.replayInitialize(ctx, initialize); err != nil {
		return err
	}
	if initialized == nil {
		return nil
	}
	msg, err := decodeMessage(initialized)
	if err != nil {
		return err
	}
	return t.postOnce(ctx, initialized, msg)
}

// replayInitialize sends the initialize request again for the session id in
// its answer. The answer itself is dropped: nobody waits for it.
func (t *HTTPTransport) replayInitialize(ctx context.Context, body []byte) error {
	ctx, release := t.requestContext(ctx)
	defer release()
	request, err := t.newRequest(ctx, http.MethodPost, bytes.NewReader(body))
	if err != nil {
		return err
	}
	response, err := t.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &HTTPStatusError{Status: response.StatusCode}
	}
	t.rememberSession(response.Header)
	return discardAnswer(response)
}

func discardAnswer(response *http.Response) error {
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaType != "text/event-stream" {
		_, err := io.Copy(io.Discard, io.LimitReader(response.Body, maxJSONResponse))
		return err
	}
	err := readEvents(response.Body, func(event sseEvent) error {
		if event.Data != "" {
			return errAnswerSeen
		}
		return nil
	})
	if errors.Is(err, errAnswerSeen) {
		return nil
	}
	return err
}
