// Package cache handles the caching hints of list results ("ttlMs" and
// "cacheScope", SEP-2549).
//
// toolward does not cache upstream results itself. The agent does, so a second
// cache here would let a result stay fresh for twice its "ttlMs". Instead the
// proxy tells the agent the weakest hint of everything a merged result was
// built from.
package cache

import "encoding/json"

// Scope says for whom a result may be cached.
type Scope string

const (
	Public  Scope = "public"
	Private Scope = "private"
)

// Hint says how long and for whom a result may be cached.
type Hint struct {
	TTLMs uint64
	Scope Scope
}

// Uncacheable is immediately stale and not shareable. It is also what a result
// without hints, from a server older than 2026-07-28, is treated as.
var Uncacheable = Hint{TTLMs: 0, Scope: Private}

// HintOf reads the hint of a raw result. A missing "ttlMs" counts as 0, and a
// missing or unknown "cacheScope" as private.
func HintOf(result json.RawMessage) Hint {
	var fields struct {
		TTLMs      *uint64 `json:"ttlMs"`
		CacheScope string  `json:"cacheScope"`
	}
	if err := json.Unmarshal(result, &fields); err != nil {
		return Uncacheable
	}
	hint := Uncacheable
	if fields.TTLMs != nil {
		hint.TTLMs = *fields.TTLMs
	}
	if fields.CacheScope == string(Public) {
		hint.Scope = Public
	}
	return hint
}

// Weakest returns the hint that holds for data from both sources.
func (h Hint) Weakest(other Hint) Hint {
	scope := Private
	if h.Scope == Public && other.Scope == Public {
		scope = Public
	}
	return Hint{TTLMs: min(h.TTLMs, other.TTLMs), Scope: scope}
}

// WeakestOf returns the hint for a result merged from several listings.
// Nothing to merge is uncacheable, because no upstream vouches for the result.
func WeakestOf(hints []Hint) Hint {
	if len(hints) == 0 {
		return Uncacheable
	}
	merged := hints[0]
	for _, hint := range hints[1:] {
		merged = merged.Weakest(hint)
	}
	return merged
}
