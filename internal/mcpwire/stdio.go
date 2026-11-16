package mcpwire

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"sync"
)

// Transport moves whole JSON-RPC messages. Read returns io.EOF when the other
// side is gone.
type Transport interface {
	Read() ([]byte, error)
	Write(message []byte) error
	Close() error
}

// StdioTransport frames messages as one JSON document per line.
type StdioTransport struct {
	reader *bufio.Reader
	writer io.Writer
	closer io.Closer

	writeMu sync.Mutex
}

// NewStdioTransport frames messages over r and w. Close closes w, and r as
// well when it can be closed.
func NewStdioTransport(r io.Reader, w io.Writer) *StdioTransport {
	return &StdioTransport{
		reader: bufio.NewReader(r),
		writer: w,
		closer: closerOf(r, w),
	}
}

func closerOf(r io.Reader, w io.Writer) io.Closer {
	var closers []io.Closer
	if c, ok := w.(io.Closer); ok {
		closers = append(closers, c)
	}
	if c, ok := r.(io.Closer); ok {
		closers = append(closers, c)
	}
	return closeAll(closers)
}

type closeAll []io.Closer

func (all closeAll) Close() error {
	var errs []error
	for _, c := range all {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

// Read returns the next non-empty line.
func (t *StdioTransport) Read() ([]byte, error) {
	for {
		line, err := t.reader.ReadBytes('\n')
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			return line, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// Write sends one message followed by a newline.
func (t *StdioTransport) Write(message []byte) error {
	framed := make([]byte, 0, len(message)+1)
	framed = append(append(framed, message...), '\n')
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, err := t.writer.Write(framed)
	return err
}

// Close closes the underlying streams.
func (t *StdioTransport) Close() error {
	return t.closer.Close()
}
