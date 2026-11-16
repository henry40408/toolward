package store

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// cacheTTL is long enough to cover the concurrent connections at startup.
const cacheTTL = 60 * time.Second

type cachedSecret struct {
	readAt time.Time
	secret string
}

// Cached reads each account from the inner store at most once and one at a time.
//
// Upstreams connect concurrently and each "${keychain:...}" reference would
// otherwise open its own OS authorization prompt. Holding the lock across the
// read queues the prompts, and the cache stops a repeated account from
// prompting again. An entry expires after the TTL, so a rotated secret is
// picked up on a later reconnect. A missing secret or a failed read is never
// cached.
type Cached struct {
	inner Store
	log   io.Writer
	ttl   time.Duration
	now   func() time.Time

	mu      sync.Mutex
	secrets map[string]cachedSecret
}

// NewCached wraps inner. A nil log discards the messages. A failed read is logged to log; the secret never is.
func NewCached(inner Store, log io.Writer) *Cached {
	if log == nil {
		log = io.Discard
	}
	return &Cached{
		inner:   inner,
		log:     log,
		ttl:     cacheTTL,
		now:     time.Now,
		secrets: map[string]cachedSecret{},
	}
}

func (c *Cached) Get(account string) (string, bool, error) {
	if err := ValidateAccount(account); err != nil {
		return "", false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if hit, ok := c.secrets[account]; ok && c.now().Sub(hit.readAt) < c.ttl {
		return hit.secret, true, nil
	}
	delete(c.secrets, account)
	return c.readThrough(account)
}

// readThrough must be called with c.mu held.
func (c *Cached) readThrough(account string) (string, bool, error) {
	secret, found, err := c.inner.Get(account)
	if err != nil {
		// Routine reads stay silent. Log only a failure, and never the secret.
		fmt.Fprintf(c.log, "toolward: reading credential store account %q failed: %v\n", account, err)
		return "", false, err
	}
	if found {
		c.secrets[account] = cachedSecret{readAt: c.now(), secret: secret}
	}
	return secret, found, nil
}

func (c *Cached) Set(account, secret string) error {
	// The lock stays held across the write so a concurrent read cannot cache the old value.
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.secrets, account)
	return c.inner.Set(account, secret)
}

func (c *Cached) Delete(account string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.secrets, account)
	return c.inner.Delete(account)
}
