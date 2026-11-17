package oauth

import (
	"net/http"
	"net/url"
	"strings"
)

// Challenge is what a WWW-Authenticate header tells about authorization.
type Challenge struct {
	// ResourceMetadataURL is the location of the protected resource metadata.
	// It is nil when the header names none, or one the host policy refuses.
	ResourceMetadataURL *url.URL
	// Scope is nil when the header has no scope parameter.
	Scope *string
}

// ParseChallenge reads the parameters of one header value, like rmcp does:
// by searching for the parameter names, not by parsing the challenge syntax.
func ParseChallenge(header string, base *url.URL) Challenge {
	var challenge Challenge
	lower := asciiLower(header)
	challenge.ResourceMetadataURL = findResourceMetadata(header, lower, base)
	if value, ok := parameterValue(header, lower, "scope="); ok {
		challenge.Scope = &value
	}
	return challenge
}

// findResourceMetadata takes the first resource_metadata value the host policy
// accepts.
func findResourceMetadata(header, lower string, base *url.URL) *url.URL {
	const key = "resource_metadata="
	offset := 0
	for {
		position := strings.Index(lower[offset:], key)
		if position < 0 {
			return nil
		}
		start := offset + position + len(key)
		value, consumed, ok := nextHeaderValue(header[start:])
		if !ok {
			return nil
		}
		if resolved := resolveResourceMetadataURL(value, base); resolved != nil {
			return resolved
		}
		offset = start + consumed
	}
}

// asciiLower keeps every byte offset, which strings.ToLower does not for all text.
func asciiLower(text string) string {
	bytes := []byte(text)
	for i, b := range bytes {
		if b >= 'A' && b <= 'Z' {
			bytes[i] = b + ('a' - 'A')
		}
	}
	return string(bytes)
}

func parameterValue(header, lower, key string) (string, bool) {
	position := strings.Index(lower, key)
	if position < 0 {
		return "", false
	}
	value, _, ok := nextHeaderValue(header[position+len(key):])
	return value, ok
}

// resolveResourceMetadataURL accepts the origin of the resource, or any URL
// the metadata host policy allows. An https resource never goes down to http.
func resolveResourceMetadataURL(value string, base *url.URL) *url.URL {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	resolved, err := base.Parse(value)
	if err != nil {
		return nil
	}
	if isHTTPURL(resolved) && sameOrigin(base, resolved) {
		return resolved
	}
	if base.Scheme == "https" && resolved.Scheme != "https" {
		return nil
	}
	if isAllowedMetadataURL(base, resolved) {
		return resolved
	}
	return nil
}

// nextHeaderValue reads a quoted string (with backslash escapes) or a token
// that ends at a comma, a semicolon or white space. consumed counts the bytes
// of the fragment that the value used, including the white space before it.
func nextHeaderValue(fragment string) (value string, consumed int, ok bool) {
	trimmed := strings.TrimLeft(fragment, " \t\r\n\v\f")
	leading := len(fragment) - len(trimmed)
	if !strings.HasPrefix(trimmed, `"`) {
		end := strings.IndexFunc(trimmed, func(r rune) bool { return r == ',' || r == ';' || isHeaderSpace(r) })
		if end < 0 {
			end = len(trimmed)
		}
		return trimmed[:end], leading + end, true
	}
	return quotedValue(trimmed[1:], leading)
}

func quotedValue(rest string, leading int) (string, int, bool) {
	var value strings.Builder
	escaped := false
	for index, char := range rest {
		switch {
		case escaped:
			value.WriteRune(char)
			escaped = false
		case char == '\\':
			escaped = true
		case char == '"':
			return value.String(), leading + index + 2, true
		default:
			value.WriteRune(char)
		}
	}
	return "", 0, false
}

func isHeaderSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f'
}

// pickChallenge chooses among the WWW-Authenticate headers of a 401: the first
// that points to resource metadata, else the first that has a scope.
func pickChallenge(headers http.Header, base *url.URL) *Challenge {
	var scopeOnly *Challenge
	for _, value := range headers.Values("WWW-Authenticate") {
		challenge := ParseChallenge(value, base)
		if challenge.ResourceMetadataURL != nil {
			return &challenge
		}
		if scopeOnly == nil && challenge.Scope != nil {
			scopeOnly = &challenge
		}
	}
	return scopeOnly
}
