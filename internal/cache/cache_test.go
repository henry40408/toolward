package cache

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

var (
	public60s = Hint{TTLMs: 60_000, Scope: Public}
	private5s = Hint{TTLMs: 5_000, Scope: Private}
)

func TestAResultWithoutHintsIsUncacheable(t *testing.T) {
	for _, result := range []string{`{}`, `{"tools": []}`, `{"cacheScope": "galactic"}`, `not json`} {
		if got := HintOf(json.RawMessage(result)); got != Uncacheable {
			t.Errorf("%s: got %+v", result, got)
		}
	}
}

func TestHintOfReadsTTLAndScope(t *testing.T) {
	got := HintOf(json.RawMessage(`{"ttlMs": 60000, "cacheScope": "public"}`))
	if got != public60s {
		t.Fatalf("got %+v", got)
	}
	got = HintOf(json.RawMessage(`{"ttlMs": 5000, "cacheScope": "private"}`))
	if got != private5s {
		t.Fatalf("got %+v", got)
	}
	got = HintOf(json.RawMessage(`{"cacheScope": "public"}`))
	if got != (Hint{TTLMs: 0, Scope: Public}) {
		t.Fatalf("scope without ttl: got %+v", got)
	}
}

func TestTheWeakestHintHasTheShortestTTLAndTheNarrowestScope(t *testing.T) {
	merged := public60s.Weakest(private5s)
	if merged != private5s {
		t.Fatalf("got %+v", merged)
	}
	if private5s.Weakest(public60s) != merged {
		t.Fatal("Weakest is not symmetric")
	}
	if public60s.Weakest(public60s) != public60s {
		t.Fatal("Weakest is not idempotent")
	}
	// A short public hint does not make a long private one public.
	shortPublic := Hint{TTLMs: 1, Scope: Public}
	longPrivate := Hint{TTLMs: 90_000, Scope: Private}
	if got := shortPublic.Weakest(longPrivate); got != (Hint{TTLMs: 1, Scope: Private}) {
		t.Fatalf("got %+v", got)
	}
}

func TestWeakestOfNothingIsUncacheable(t *testing.T) {
	if got := WeakestOf(nil); got != Uncacheable {
		t.Fatalf("got %+v", got)
	}
	if got := WeakestOf([]Hint{public60s}); got != public60s {
		t.Fatalf("got %+v", got)
	}
	if got := WeakestOf([]Hint{public60s, private5s, public60s}); got != private5s {
		t.Fatalf("got %+v", got)
	}
}

func page(next string, hint Hint) Page[int] {
	return Page[int]{Items: []int{1}, NextCursor: next, Hint: hint}
}

func TestPagesAreFollowedAndTheirHintsMerged(t *testing.T) {
	var cursors []string
	listed, err := CollectPages(context.Background(), func(_ context.Context, cursor string) (Page[int], error) {
		cursors = append(cursors, cursor)
		switch cursor {
		case "":
			return page("b", public60s), nil
		case "b":
			return page("c", private5s), nil
		}
		return page("", public60s), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(listed.Items, []int{1, 1, 1}) {
		t.Fatalf("items = %v", listed.Items)
	}
	if listed.Hint != private5s {
		t.Fatalf("hint = %+v", listed.Hint)
	}
	if !slices.Equal(cursors, []string{"", "b", "c"}) {
		t.Fatalf("cursors = %q", cursors)
	}
}

func TestAFailedPageFailsTheListing(t *testing.T) {
	boom := errors.New("boom")
	_, err := CollectPages(context.Background(), func(_ context.Context, cursor string) (Page[int], error) {
		if cursor == "" {
			return page("b", public60s), nil
		}
		return Page[int]{}, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}

func TestACancelledContextStopsAnEndlessCursor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, err := CollectPages(ctx, func(_ context.Context, _ string) (Page[int], error) {
		calls++
		cancel()
		return page("again", public60s), nil
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("calls = %d, err = %v", calls, err)
	}
}

func TestNextCursorOf(t *testing.T) {
	if got := NextCursorOf(json.RawMessage(`{"nextCursor": "abc"}`)); got != "abc" {
		t.Fatalf("got %q", got)
	}
	if got := NextCursorOf(json.RawMessage(`{}`)); got != "" {
		t.Fatalf("got %q", got)
	}
}
