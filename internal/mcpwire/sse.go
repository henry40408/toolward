package mcpwire

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const maxEventSize = 16 * 1024 * 1024

// sseEvent is one server-sent event. Data is empty for events that only carry
// an id or a retry delay.
type sseEvent struct {
	// Type is empty for the default "message" event.
	Type string
	Data string
	// ID is the last event id seen, which carries over to later events.
	ID string
	// Retry is the reconnection delay the server asked for, or zero.
	Retry time.Duration
}

var errEventTooLarge = errors.New("server-sent event exceeds the size limit")

// readEvents calls handle for each event until the stream ends. A clean end
// gives nil.
func readEvents(r io.Reader, handle func(sseEvent) error) error {
	reader := bufio.NewReader(r)
	var current eventBuilder
	for {
		line, err := readLine(reader)
		if err != nil {
			return endOfStream(err)
		}
		if line != "" {
			if err := current.addLine(line); err != nil {
				return err
			}
			continue
		}
		if event, ok := current.take(); ok {
			if err := handle(event); err != nil {
				return err
			}
		}
	}
}

func endOfStream(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// readLine returns a line without its terminator. It fails when the stream
// ends in the middle of a line, which drops that partial line.
func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

// eventBuilder collects the fields of the event being read.
type eventBuilder struct {
	touched   bool
	eventType string
	data      []string
	size      int
	id        string
	retry     time.Duration
}

func (b *eventBuilder) addLine(line string) error {
	if strings.HasPrefix(line, ":") {
		return nil
	}
	field, value, _ := strings.Cut(line, ":")
	value = strings.TrimPrefix(value, " ")
	switch field {
	case "event":
		b.eventType = value
		b.touched = true
	case "data":
		b.touched = true
		return b.addData(value)
	case "id":
		b.setID(value)
	case "retry":
		b.setRetry(value)
	}
	return nil
}

func (b *eventBuilder) addData(value string) error {
	b.size += len(value) + 1
	if b.size > maxEventSize {
		return fmt.Errorf("%w (%d bytes)", errEventTooLarge, maxEventSize)
	}
	b.data = append(b.data, value)
	return nil
}

func (b *eventBuilder) setID(value string) {
	if strings.Contains(value, "\x00") {
		return
	}
	b.id = value
	b.touched = true
}

func (b *eventBuilder) setRetry(value string) {
	millis, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return
	}
	b.retry = time.Duration(millis) * time.Millisecond
	b.touched = true
}

// take returns the finished event and starts the next one. The id stays,
// because it names the stream position until a later event changes it.
func (b *eventBuilder) take() (sseEvent, bool) {
	event := sseEvent{Type: b.eventType, Data: strings.Join(b.data, "\n"), ID: b.id, Retry: b.retry}
	touched := b.touched
	*b = eventBuilder{id: b.id}
	return event, touched
}
