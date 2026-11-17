// Package names chooses the names the agent sees for upstream tools.
//
// A tool is exposed as "<server>__<tool>". Clients prepend their own prefix
// ("mcp__toolward__" in Claude Code) and some cap the whole name at 64
// characters, so the part toolward controls is kept within Budget. Names that
// are too long, or that contain characters some clients rewrite, become
// "<server>__<stem>_<hash>", where the hash is derived from the original name.
// A name that collides with another one gets a longer hash, so adding a tool
// can rename another tool that collides with it.
package names

import (
	"crypto/sha256"
	"strings"
)

const (
	// Separator separates the server name from the tool name. Server names
	// cannot contain it.
	Separator = "__"
	// Budget is the longest "<server>__<tool>" toolward emits: 64 minus the 15
	// characters of "mcp__toolward__", the strictest client we know of (pi).
	Budget = 49
	// HashLen is the number of characters of the base32 hash suffix. 8
	// characters are 40 bits.
	HashLen = 8
	// maxHashLen is the number of whole base32 characters of a SHA-256 digest.
	maxHashLen = 51
)

// Pair is an exposed tool part and the original tool name behind it.
type Pair struct {
	Exposed  string
	Original string
}

// Assignment is the result of naming one server's tools.
type Assignment struct {
	// Names are in input order. The agent sees "<server>__<Exposed>".
	Names []Pair
	// Dropped holds original names that could not get a unique exposed name.
	Dropped []string
}

// Sanitize replaces every character outside [A-Za-z0-9_-] with "_".
func Sanitize(name string) string {
	var b strings.Builder
	for _, r := range name {
		if isSafe(r) {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	return b.String()
}

func isSafe(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-'
}

// Assign names the tools of server. originals are the names the upstream reports.
func Assign(server string, originals []string) Assignment {
	return assignWith(server, originals, sha256Digest)
}

func sha256Digest(server, tool string) []byte {
	h := sha256.New()
	h.Write([]byte(server))
	h.Write([]byte{0})
	h.Write([]byte(tool))
	return h.Sum(nil)
}

// truncateStem cuts the ASCII stem to at most limit bytes, preferring a "_" boundary.
func truncateStem(stem string, limit int) string {
	if len(stem) <= limit {
		return stem
	}
	cut := stem[:limit]
	if i := strings.LastIndexByte(cut, '_'); i > 0 {
		return cut[:i]
	}
	return cut
}

type entry struct {
	original string
	stem     string
	plain    bool // the original name is used as is
	hashLen  int
	digest   []byte
}

func (e *entry) exposed(room int) string {
	if e.plain {
		return e.original
	}
	hash := base32Prefix(e.digest, e.hashLen)
	available := max(room-(e.hashLen+1), 1)
	return truncateStem(e.stem, available) + "_" + hash
}

func newEntry(original string, room, hashLen int, digest []byte) *entry {
	stem := Sanitize(original)
	plain := original != "" && stem == original && len(original) <= room
	if stem == "" {
		stem = "_"
	}
	return &entry{original: original, stem: stem, plain: plain, hashLen: hashLen, digest: digest}
}

// collidingGroups returns the indexes of the entries that share an exposed
// name, one group per name, in first-seen order. Dropped entries are ignored.
func collidingGroups(entries []*entry, dropped []bool, room int) [][]int {
	seen := map[string][]int{}
	var order []string
	for i, e := range entries {
		if dropped[i] {
			continue
		}
		name := e.exposed(room)
		if _, ok := seen[name]; !ok {
			order = append(order, name)
		}
		seen[name] = append(seen[name], i)
	}
	var groups [][]int
	for _, name := range order {
		if len(seen[name]) > 1 {
			groups = append(groups, seen[name])
		}
	}
	return groups
}

// widenGroups grows the hash of every hashed member and reports whether any grew.
func widenGroups(entries []*entry, groups [][]int, maxHash int) bool {
	changed := false
	for _, group := range groups {
		for _, i := range group {
			e := entries[i]
			if e.plain || e.hashLen >= maxHash {
				continue
			}
			e.hashLen = min(e.hashLen+4, maxHash)
			changed = true
		}
	}
	return changed
}

// widenCollidingHashes gives colliding names a longer hash. Each round grows
// the hash of every colliding hashed name; the loop ends when nothing can
// grow. It returns, per entry, whether it was dropped because it still collides.
func widenCollidingHashes(entries []*entry, room, maxHash int) []bool {
	dropped := make([]bool, len(entries))
	for {
		groups := collidingGroups(entries, dropped, room)
		if widenGroups(entries, groups, maxHash) {
			continue
		}
		// Whatever still collides cannot be told apart: keep the first.
		for _, group := range groups {
			for _, i := range group[1:] {
				dropped[i] = true
			}
		}
		return dropped
	}
}

func assignWith(server string, originals []string, digest func(server, tool string) []byte) Assignment {
	room := max(Budget-(len(server)+len(Separator)), 0)
	maxHash := max(min(maxHashLen, max(room-2, 0)), 1)
	entries := make([]*entry, len(originals))
	for i, original := range originals {
		entries[i] = newEntry(original, room, min(HashLen, maxHash), digest(server, original))
	}

	dropped := widenCollidingHashes(entries, room, maxHash)

	var a Assignment
	for i, e := range entries {
		if dropped[i] {
			a.Dropped = append(a.Dropped, e.original)
			continue
		}
		a.Names = append(a.Names, Pair{Exposed: e.exposed(room), Original: e.original})
	}
	return a
}
