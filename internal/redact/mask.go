// Package redact hides secret values in text and in upstream results.
package redact

import (
	"slices"
	"strings"
)

// Mask replaces every masked secret.
const Mask = "[REDACTED]"

// span is a half-open byte range of the text.
type span struct{ start, end int }

// Redact replaces every secret value in text with Mask.
func Redact(text string, secrets []string) string {
	patterns := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret != "" {
			patterns = append(patterns, secret)
		}
	}
	masked, changed := maskText(text, patterns)
	if !changed {
		return text
	}
	return masked
}

// maskText replaces every match of every pattern with Mask and reports whether
// anything matched. Matches that overlap or touch become one mask, so no part
// of a secret that overlaps another one is left behind.
func maskText(text string, patterns []string) (string, bool) {
	spans := matchSpans(text, patterns)
	if len(spans) == 0 {
		return text, false
	}
	var out strings.Builder
	copied := 0
	for _, merged := range mergeSpans(spans) {
		out.WriteString(text[copied:merged.start])
		out.WriteString(Mask)
		copied = merged.end
	}
	out.WriteString(text[copied:])
	return out.String(), true
}

// matchSpans lists the non-overlapping matches of each pattern, sorted by position.
func matchSpans(text string, patterns []string) []span {
	var spans []span
	for _, pattern := range patterns {
		spans = append(spans, matchesOf(text, pattern)...)
	}
	slices.SortFunc(spans, func(a, b span) int {
		if a.start != b.start {
			return a.start - b.start
		}
		return a.end - b.end
	})
	return spans
}

func matchesOf(text, pattern string) []span {
	if pattern == "" {
		return nil
	}
	var spans []span
	offset := 0
	for {
		index := strings.Index(text[offset:], pattern)
		if index < 0 {
			return spans
		}
		start := offset + index
		offset = start + len(pattern)
		spans = append(spans, span{start, offset})
	}
}

// mergeSpans joins sorted spans that overlap or touch.
func mergeSpans(spans []span) []span {
	merged := []span{spans[0]}
	for _, next := range spans[1:] {
		last := &merged[len(merged)-1]
		if next.start > last.end {
			merged = append(merged, next)
			continue
		}
		last.end = max(last.end, next.end)
	}
	return merged
}
