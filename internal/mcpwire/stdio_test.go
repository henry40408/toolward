package mcpwire

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestStdioReadSkipsEmptyLines(t *testing.T) {
	transport := NewStdioTransport(strings.NewReader("\n{\"a\":1}\r\n\n{\"b\":2}"), io.Discard)
	for _, want := range []string{`{"a":1}`, `{"b":2}`} {
		got, err := transport.Read()
		if err != nil || string(got) != want {
			t.Fatalf("Read = %q, %v; want %q", got, err, want)
		}
	}
	if _, err := transport.Read(); !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want EOF", err)
	}
}

func TestStdioReadsLongMessages(t *testing.T) {
	long := `{"text":"` + strings.Repeat("x", 1<<20) + `"}`
	transport := NewStdioTransport(strings.NewReader(long+"\n"), io.Discard)
	got, err := transport.Read()
	if err != nil || string(got) != long {
		t.Fatalf("Read failed: %v (len %d)", err, len(got))
	}
}

func TestStdioWriteAddsNewline(t *testing.T) {
	var out bytes.Buffer
	transport := NewStdioTransport(strings.NewReader(""), &out)
	if err := transport.Write([]byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if out.String() != "{\"a\":1}\n" {
		t.Errorf("out = %q", out.String())
	}
}
