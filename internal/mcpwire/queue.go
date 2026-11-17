package mcpwire

import (
	"io"
	"sync"
)

// messageQueue hands messages from the goroutines that receive them to Read.
// It never blocks a sender: a handler may be sending a request while the
// reader is busy running another handler.
type messageQueue struct {
	mu     sync.Mutex
	ready  *sync.Cond
	items  [][]byte
	closed bool
	err    error
}

func newMessageQueue() *messageQueue {
	queue := &messageQueue{}
	queue.ready = sync.NewCond(&queue.mu)
	return queue
}

func (q *messageQueue) push(message []byte) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.items = append(q.items, message)
	q.ready.Signal()
}

// pop waits for the next message. Messages queued before close are still
// returned; then the error given to close, or io.EOF.
func (q *messageQueue) pop() ([]byte, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.ready.Wait()
	}
	if len(q.items) > 0 {
		message := q.items[0]
		q.items = q.items[1:]
		return message, nil
	}
	if q.err != nil {
		return nil, q.err
	}
	return nil, io.EOF
}

// close ends the queue. The first call decides the error.
func (q *messageQueue) close(err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	q.err = err
	q.ready.Broadcast()
}
