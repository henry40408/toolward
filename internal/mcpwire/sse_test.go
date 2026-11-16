package mcpwire

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReadEvents(t *testing.T) {
	tests := []struct {
		name   string
		stream string
		want   []sseEvent
	}{
		{"one event", "data: {\"a\":1}\n\n", []sseEvent{{Data: `{"a":1}`}}},
		{"crlf", "data: x\r\n\r\n", []sseEvent{{Data: "x"}}},
		{"data lines are joined", "data: a\ndata: b\n\n", []sseEvent{{Data: "a\nb"}}},
		{"type and id", "event: message\nid: 7\ndata: x\n\n", []sseEvent{{Type: "message", ID: "7", Data: "x"}}},
		{"comments are skipped", ": ping\ndata: x\n\n", []sseEvent{{Data: "x"}}},
		{"retry without data", "retry: 1500\nid: 3\n\n", []sseEvent{{ID: "3", Retry: 1500 * time.Millisecond}}},
		{"the id carries over", "id: 1\ndata: a\n\ndata: b\n\n", []sseEvent{{ID: "1", Data: "a"}, {ID: "1", Data: "b"}}},
		{"no space after the colon", "data:x\n\n", []sseEvent{{Data: "x"}}},
		{"an event cut off is dropped", "data: a\n\ndata: b", []sseEvent{{Data: "a"}}},
		{"a bad retry is ignored", "retry: soon\ndata: x\n\n", []sseEvent{{Data: "x"}}},
		{"empty lines alone give nothing", "\n\n\n", nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got []sseEvent
			err := readEvents(strings.NewReader(test.stream), func(event sseEvent) error {
				got = append(got, event)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("events = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestReadEventsStopsWhenTheHandlerFails(t *testing.T) {
	stop := errors.New("stop")
	err := readEvents(strings.NewReader("data: a\n\ndata: b\n\n"), func(sseEvent) error { return stop })
	if !errors.Is(err, stop) {
		t.Errorf("err = %v", err)
	}
}

func TestReadEventsRefusesAnEventOverTheLimit(t *testing.T) {
	line := "data: " + strings.Repeat("x", maxEventSize/2) + "\n"
	err := readEvents(strings.NewReader(line+line+line+"\n"), func(sseEvent) error { return nil })
	if !errors.Is(err, errEventTooLarge) {
		t.Errorf("err = %v", err)
	}
}
