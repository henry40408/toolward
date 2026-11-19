package mcpwire

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

var errResumeRefused = errors.New("the server did not resume the stream")

type streamOutcome int

const (
	streamOpen streamOutcome = iota
	streamEnded
	streamFailed
	streamUnsupported
	streamExpired
)

// streamPosition is what carries over from one connection of a stream to the
// next.
type streamPosition struct {
	lastEventID string
	retry       time.Duration
}

func (p *streamPosition) observe(event sseEvent) {
	if event.ID != "" {
		p.lastEventID = event.ID
	}
	if event.Retry > 0 {
		p.retry = event.Retry
	}
}

// answerStream follows the answer to one request over its POST stream, and
// over the GET streams that resume it.
type answerStream struct {
	streamPosition
	sent     message
	answered bool
	gaveUp   bool
	// events counts the events read, to tell whether a connection made progress.
	events int
}

// canResume needs an event id: without one the server cannot tell where to
// continue.
func (s *answerStream) canResume() bool {
	return !s.answered && !s.gaveUp && s.lastEventID != ""
}

// pumpResponseStream reads the events of a POST answer. A stream that ends
// before the answer is resumed when the server gave an event id (SEP-1699:
// servers close the stream to make clients poll). Otherwise the caller would
// wait for ever, so it is answered with an error.
func (t *HTTPTransport) pumpResponseStream(response *http.Response, sent message, release func()) {
	defer release()
	ctx := response.Request.Context()
	stream := &answerStream{streamPosition: streamPosition{retry: defaultStreamRetry}, sent: sent}
	err := t.readAnswer(response.Body, stream)
	_ = response.Body.Close()
	if sent.kind() != kindRequest {
		return
	}
	err = t.resumeAnswer(ctx, stream, err)
	if stream.answered {
		return
	}
	t.queue.push(streamEndedError(sent.ID, err))
}

func (t *HTTPTransport) readAnswer(body io.Reader, stream *answerStream) error {
	return readEvents(body, func(event sseEvent) error {
		stream.events++
		stream.observe(event)
		msg := t.receiveEvent(event)
		stream.answered = stream.answered || (msg.kind() == kindResponse && idKey(msg.ID) == idKey(stream.sent.ID))
		return nil
	})
}

// resumeAnswer reconnects until the answer arrives, the stream makes no
// progress maxStreamFailures times in a row, or ctx ends. It returns the
// reason that the last connection ended.
func (t *HTTPTransport) resumeAnswer(ctx context.Context, stream *answerStream, cause error) error {
	for failures := 0; stream.canResume() && failures < maxStreamFailures; {
		if !sleep(ctx, stream.retry) {
			return ctx.Err()
		}
		before := stream.events
		cause = t.resumeOnce(ctx, stream)
		if stream.events > before {
			failures = 0
			continue
		}
		failures++
	}
	return cause
}

// resumeOnce reads one connection of a resumed answer.
func (t *HTTPTransport) resumeOnce(ctx context.Context, stream *answerStream) error {
	response, outcome := t.getStream(ctx, stream.lastEventID)
	switch outcome {
	case streamExpired:
		stream.gaveUp = true
		return t.expireSession()
	case streamUnsupported:
		stream.gaveUp = true
	}
	if outcome != streamOpen {
		return errResumeRefused
	}
	defer func() { _ = response.Body.Close() }()
	return t.readAnswer(response.Body, stream)
}

// getStream opens a GET stream. The response is set only when the outcome is
// streamOpen.
func (t *HTTPTransport) getStream(ctx context.Context, lastEventID string) (*http.Response, streamOutcome) {
	request, err := t.newRequest(ctx, http.MethodGet, nil)
	if err != nil {
		return nil, streamFailed
	}
	if version := t.negotiatedVersion(); version != "" {
		request.Header.Set(headerProtocolVersion, version)
	}
	if lastEventID != "" {
		request.Header.Set(headerLastEventID, lastEventID)
	}
	response, err := t.client.Do(request)
	if err != nil {
		return nil, streamFailed
	}
	outcome := t.classifyStream(response)
	if outcome != streamOpen {
		_ = response.Body.Close()
		return nil, outcome
	}
	return response, streamOpen
}

// classifyStream tells what an answer to a stream request means. A 404 is an
// expired session only while the session it named is still the current one,
// else another call has opened a new one already.
func (t *HTTPTransport) classifyStream(response *http.Response) streamOutcome {
	switch response.StatusCode {
	case http.StatusOK:
		if hasMediaType(response, "text/event-stream") {
			return streamOpen
		}
		return streamUnsupported
	case http.StatusMethodNotAllowed:
		return streamUnsupported
	case http.StatusNotFound:
		if id := response.Request.Header.Get(headerSessionID); id != "" && id == t.session() {
			return streamExpired
		}
	}
	return streamFailed
}

func sleep(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (t *HTTPTransport) listen() {
	state := &streamPosition{retry: defaultStreamRetry}
	for failures := 0; failures < maxStreamFailures; {
		switch t.openServerStream(state) {
		case streamUnsupported:
			return
		case streamExpired:
			_ = t.expireSession()
			return
		case streamFailed:
			failures++
		case streamEnded:
			failures = 0
		}
		if !sleep(t.ctx, state.retry) {
			return
		}
	}
}

// openServerStream reads one connection of the standalone stream. A server may
// answer 405 to say that it has no such stream.
func (t *HTTPTransport) openServerStream(state *streamPosition) streamOutcome {
	response, outcome := t.getStream(t.ctx, state.lastEventID)
	if outcome != streamOpen {
		return outcome
	}
	defer func() { _ = response.Body.Close() }()
	err := readEvents(response.Body, func(event sseEvent) error {
		state.observe(event)
		t.receiveEvent(event)
		return nil
	})
	if err != nil {
		return streamFailed
	}
	return streamEnded
}
