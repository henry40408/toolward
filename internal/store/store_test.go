package store

import (
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAccountValidation(t *testing.T) {
	for _, ok := range []string{"github", "a.b_c-1"} {
		if err := ValidateAccount(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "a/b", "a:b", "${x}", "é"} {
		if err := ValidateAccount(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestInvalidAccountMessage(t *testing.T) {
	err := ValidateAccount("a b")
	want := `invalid account name "a b": use only ASCII letters, digits, '.', '_' and '-'`
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %s", err, want)
	}
}

func TestOAuthAccountsAreReservedForLogins(t *testing.T) {
	for _, reserved := range []string{"oauth.sentry", "oauth-client.sentry"} {
		var target *ReservedAccountError
		if err := ValidateUserAccount(reserved); !errors.As(err, &target) {
			t.Errorf("%q: got %v", reserved, err)
		}
		if err := ValidateAccount(reserved); err != nil {
			t.Errorf("%q: %v", reserved, err)
		}
	}
	if err := ValidateUserAccount("github"); err != nil {
		t.Fatal(err)
	}
}

func TestReservedMessage(t *testing.T) {
	err := ValidateUserAccount("oauth.x")
	want := `account names starting with "oauth." or "oauth-client." are reserved for OAuth logins: "oauth.x"`
	if err == nil || err.Error() != want {
		t.Fatalf("got %v", err)
	}
}

func TestMemoryStoreRoundTrip(t *testing.T) {
	s := NewMemory()
	if _, found, err := s.Get("a"); found || err != nil {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if err := s.Set("a", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if got, found, _ := s.Get("a"); !found || got != "s3cret" {
		t.Fatalf("got %q %v", got, found)
	}
	if removed, _ := s.Delete("a"); !removed {
		t.Fatal("delete reported nothing removed")
	}
	if removed, _ := s.Delete("a"); removed {
		t.Fatal("second delete removed something")
	}
	if _, found, _ := s.Get("a"); found {
		t.Fatal("secret still there")
	}
}

func TestMemoryStoreRejectsABadAccount(t *testing.T) {
	var target *InvalidAccountError
	if err := NewMemory().Set("bad/name", "x"); !errors.As(err, &target) {
		t.Fatalf("got %v", err)
	}
}

// probe counts reads and notes whether two reads overlapped.
type probe struct {
	reads      atomic.Int32
	active     atomic.Int32
	overlapped atomic.Bool
}

func (p *probe) Get(string) (string, bool, error) {
	p.reads.Add(1)
	if p.active.Add(1) > 1 {
		p.overlapped.Store(true)
	}
	time.Sleep(30 * time.Millisecond)
	p.active.Add(-1)
	return "s3cret", true, nil
}

func (*probe) Set(string, string) error    { return nil }
func (*probe) Delete(string) (bool, error) { return true, nil }

func newCached(inner Store) *Cached {
	return NewCached(inner, io.Discard)
}

func TestCachedReadsOnceAndOneAtATime(t *testing.T) {
	inner := &probe{}
	c := newCached(inner)
	var wg sync.WaitGroup
	for i := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Two distinct accounts, each asked for three times.
			got, _, err := c.Get([]string{"acct0", "acct1"}[i%2])
			if err != nil || got != "s3cret" {
				t.Errorf("got %q, %v", got, err)
			}
		}()
	}
	wg.Wait()
	if n := inner.reads.Load(); n != 2 {
		t.Fatalf("reads = %d, want 2", n)
	}
	if inner.overlapped.Load() {
		t.Fatal("reads overlapped")
	}
}

func TestCachedForgetsAnAccountAfterSet(t *testing.T) {
	inner := &probe{}
	c := newCached(inner)
	_, _, _ = c.Get("a")
	_ = c.Set("a", "new")
	_, _, _ = c.Get("a")
	if n := inner.reads.Load(); n != 2 {
		t.Fatalf("reads = %d, want 2", n)
	}
}

func TestCachedForgetsAnAccountAfterDelete(t *testing.T) {
	inner := &probe{}
	c := newCached(inner)
	_, _, _ = c.Get("a")
	_, _ = c.Delete("a")
	_, _, _ = c.Get("a")
	if n := inner.reads.Load(); n != 2 {
		t.Fatalf("reads = %d, want 2", n)
	}
}

func TestCachedDoesNotRememberAMissingSecret(t *testing.T) {
	inner := NewMemory()
	c := newCached(inner)
	if _, found, _ := c.Get("late"); found {
		t.Fatal("found a secret that does not exist")
	}
	// Stored behind the cache's back, as `toolward secret set` would.
	_ = inner.Set("late", "now")
	if got, found, _ := c.Get("late"); !found || got != "now" {
		t.Fatalf("got %q %v", got, found)
	}
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func TestCachedRereadsOnceAfterExpiryThenCachesAgain(t *testing.T) {
	inner := &probe{}
	clk := &clock{now: time.Unix(1000, 0)}
	c := newCached(inner)
	c.now = clk.Now
	_, _, _ = c.Get("a")
	_, _, _ = c.Get("a")
	if n := inner.reads.Load(); n != 1 {
		t.Fatalf("reads = %d, want 1", n)
	}
	clk.now = clk.now.Add(cacheTTL - time.Nanosecond)
	_, _, _ = c.Get("a")
	if n := inner.reads.Load(); n != 1 {
		t.Fatalf("an entry just inside the TTL was re-read: %d", n)
	}
	clk.now = clk.now.Add(time.Nanosecond)
	for range 5 {
		if got, _, _ := c.Get("a"); got != "s3cret" {
			t.Fatalf("got %q", got)
		}
	}
	if n := inner.reads.Load(); n != 2 {
		t.Fatalf("reads = %d, want 2", n)
	}
}

type failing struct{ reads atomic.Int32 }

func (f *failing) Get(string) (string, bool, error) {
	f.reads.Add(1)
	return "", false, &BackendError{Message: "boom"}
}
func (*failing) Set(string, string) error    { return nil }
func (*failing) Delete(string) (bool, error) { return false, nil }

func TestCachedDoesNotCacheAnInnerFailureAndLogsIt(t *testing.T) {
	inner := &failing{}
	var log strings.Builder
	c := NewCached(inner, &log)
	for range 2 {
		if _, _, err := c.Get("a"); err == nil {
			t.Fatal("expected an error")
		}
	}
	if n := inner.reads.Load(); n != 2 {
		t.Fatalf("reads = %d, want 2", n)
	}
	want := "toolward: reading credential store account \"a\" failed: credential store failure: boom\n"
	if !strings.HasPrefix(log.String(), want) {
		t.Fatalf("log = %q", log.String())
	}
}

func TestCachedRejectsABadAccountBeforeReading(t *testing.T) {
	inner := &probe{}
	if _, _, err := newCached(inner).Get("bad/name"); err == nil {
		t.Fatal("expected an error")
	}
	if inner.reads.Load() != 0 {
		t.Fatal("the inner store was read")
	}
}

func TestCachedWithNilLogSurvivesAFailedRead(t *testing.T) {
	if _, _, err := NewCached(&failing{}, nil).Get("a"); err == nil {
		t.Fatal("expected an error")
	}
}
