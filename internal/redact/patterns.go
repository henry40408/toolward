package redact

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
)

const (
	// minResultSecretLen is the length under which secrets are not masked in
	// results: they would match ordinary text, and a value that short is no
	// secret worth hiding.
	minResultSecretLen = 4
	// minLineSecretLen is the length a line of a multi-line secret must have
	// to be masked alone.
	minLineSecretLen = 8
)

// resultPatterns returns every form in which a secret may appear inside a JSON
// string value: as is, JSON-escaped (when the text is itself JSON),
// percent-encoded (in URLs) and base64-encoded. Longest first, so a secret that
// contains another one is fully masked.
func resultPatterns(secrets []string) []string {
	var patterns []string
	for _, secret := range secretsWithLines(secrets) {
		patterns = append(patterns, secret)
		patterns = append(patterns, jsonForms(secret)...)
		patterns = append(patterns, percentEncode(secret, upperHex), percentEncode(secret, lowerHex))
		patterns = append(patterns, base64Forms([]byte(secret))...)
	}
	patterns = slices.DeleteFunc(patterns, func(p string) bool { return len(p) < minResultSecretLen })
	slices.SortStableFunc(patterns, func(a, b string) int { return len(b) - len(a) })
	return slices.Compact(patterns)
}

// secretsWithLines returns the secrets long enough to mask, and every line of
// them. A multi-line secret (PEM key, JSON key file) may come back one line at
// a time, so every line of it counts as a secret too.
func secretsWithLines(secrets []string) []string {
	var whole []string
	for _, secret := range secrets {
		if len(secret) >= minResultSecretLen {
			whole = append(whole, secret)
		}
	}
	all := slices.Clone(whole)
	for _, secret := range whole {
		for _, line := range strings.Split(secret, "\n") {
			line = strings.TrimSpace(line)
			if len(line) >= minLineSecretLen {
				all = append(all, line)
			}
		}
	}
	return all
}

// jsonForms returns the secret as a JSON string body, with the slash escaped
// the way some encoders (PHP) do, and escaped twice (JSON inside a JSON string,
// as a tool that returns a JSON document does).
func jsonForms(secret string) []string {
	inner := jsonEscape(secret)
	return []string{
		inner,
		strings.ReplaceAll(inner, "/", `\/`),
		jsonEscape(inner),
	}
}

// jsonEscape escapes s as the inside of a JSON string: only
// quotes, backslashes and control characters change. Unlike encoding/json it
// leaves <, > and & alone.
func jsonEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		writeJSONByte(&b, s[i])
	}
	return b.String()
}

func writeJSONByte(b *strings.Builder, c byte) {
	switch c {
	case '"':
		b.WriteString(`\"`)
	case '\\':
		b.WriteString(`\\`)
	case '\b':
		b.WriteString(`\b`)
	case '\f':
		b.WriteString(`\f`)
	case '\n':
		b.WriteString(`\n`)
	case '\r':
		b.WriteString(`\r`)
	case '\t':
		b.WriteString(`\t`)
	default:
		if c < 0x20 {
			fmt.Fprintf(b, `\u%04x`, c)
			return
		}
		b.WriteByte(c)
	}
}

const (
	upperHex = "%%%02X"
	lowerHex = "%%%02x"
)

// percentEncode encodes every byte outside the unreserved set (A-Za-z0-9-._~).
func percentEncode(s, format string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, format, c)
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// base64Encode encodes with the standard alphabet and no padding.
func base64Encode(data []byte) string {
	return base64.RawStdEncoding.EncodeToString(data)
}

// base64Forms returns the text a secret becomes inside base64 data, whatever
// its alignment. Only the characters that depend on the secret alone are kept.
func base64Forms(secret []byte) []string {
	starts := [3]int{0, 2, 3}
	var forms []string
	for offset := range 3 {
		encoded := base64Encode(append(make([]byte, offset), secret...))
		start := starts[offset]
		tail := 0
		if (offset+len(secret))%3 != 0 {
			tail = 1
		}
		if len(encoded) > start+tail {
			forms = append(forms, encoded[start:len(encoded)-tail])
		}
	}
	return forms
}
