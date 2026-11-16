package importer

import (
	"fmt"
	"strings"
)

// secretWords: a name containing one of these (any case) holds a secret.
var secretWords = []string{
	"token", "secret", "key", "password", "passwd", "auth",
	"credential", "cookie", "signature", "bearer",
}

// secretTokens are short words that only count as a whole word (`PAT` but not
// `PATH`).
var secretTokens = []string{"pass", "pwd", "pat", "dsn", "jwt", "session", "private"}

// secretPrefixes are the value prefixes of well-known credentials.
var secretPrefixes = []string{
	"ghp_", "gho_", "ghu_", "ghs_", "github_pat_", "sk-",
	"xoxb-", "xoxp-", "xoxa-", "glpat-", "AKIA",
}

func looksSecret(name string) bool {
	name = asciiLower(name)
	for _, word := range secretWords {
		if strings.Contains(name, word) {
			return true
		}
	}
	for _, part := range strings.FieldsFunc(name, func(char rune) bool { return !isASCIIAlphanumeric(char) }) {
		if contains(secretTokens, part) {
			return true
		}
	}
	return false
}

func hasSecretPrefix(value string) bool {
	for _, prefix := range secretPrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func isASCIIAlphanumeric(char rune) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
}

// asciiLower lowers ASCII letters only, so that no other character changes.
func asciiLower(text string) string {
	return strings.Map(func(char rune) rune {
		if char >= 'A' && char <= 'Z' {
			return char + ('a' - 'A')
		}
		return char
	}, text)
}

// inlineSecret says why a field that cannot hold a reference carries a
// secret, or gives "" when none does.
func inlineSecret(server object) string {
	if url, ok := server["url"].(string); ok {
		if reason := urlSecret(url); reason != "" {
			return reason
		}
	}
	args, ok := server["args"].([]any)
	if !ok {
		return ""
	}
	for _, arg := range args {
		if text, ok := arg.(string); ok {
			if reason := argSecret(text); reason != "" {
				return reason
			}
		}
	}
	return ""
}

func urlSecret(url string) string {
	rest := url
	if _, after, found := strings.Cut(url, "://"); found {
		rest = after
	}
	authority, _, _ := strings.Cut(rest, "/")
	authority, _, _ = strings.Cut(authority, "?")
	authority, _, _ = strings.Cut(authority, "#")
	if strings.Contains(authority, "@") {
		return "its url contains a user name or password"
	}
	_, query, found := strings.Cut(url, "?")
	if found && queryHoldsSecret(query) {
		return "its url contains a secret in the query"
	}
	return ""
}

func queryHoldsSecret(query string) bool {
	for _, pair := range strings.Split(query, "&") {
		key, value, _ := strings.Cut(pair, "=")
		if looksSecret(key) || hasSecretPrefix(value) {
			return true
		}
	}
	return false
}

func argSecret(arg string) string {
	flag, value, _ := strings.Cut(arg, "=")
	// Why: the flag name is echoed, so a value glued to the flag (`--ghp_...`)
	// would leak. Rust does the same; revisit both together.
	if strings.HasPrefix(flag, "--") && looksSecret(flag) {
		return fmt.Sprintf("argument %s looks like it holds a secret", flag)
	}
	if hasSecretPrefix(arg) || hasSecretPrefix(value) {
		return "an argument looks like a secret"
	}
	return ""
}
