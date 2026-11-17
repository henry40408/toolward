package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/henry40408/toolward/internal/interpolate"
)

// MaxNameLen is the longest server name. Tool names are capped (see
// names.Budget), and the server name is a part of each, so it must leave room
// for the tool.
const MaxNameLen = 20

// ServerError is a problem with one server entry.
type ServerError struct {
	Name string
	Err  error
}

func (e *ServerError) Error() string { return fmt.Sprintf("server %q: %v", e.Name, e.Err) }
func (e *ServerError) Unwrap() error { return e.Err }

func serverError(name, reason string) error {
	return &ServerError{Name: name, Err: errors.New(reason)}
}

func (c *Config) validate() error {
	if err := c.checkFoldedNames(); err != nil {
		return err
	}
	for _, name := range c.Names() {
		if err := checkServerFields(name, c.Servers[name]); err != nil {
			return err
		}
	}
	return nil
}

// checkFoldedNames rejects names that differ only by '-' versus '_': some
// clients turn '-' into '_' (Codex, pi), so "a-b" and "a_b" would clash.
func (c *Config) checkFoldedNames() error {
	folded := map[string]string{}
	for _, name := range c.Names() {
		key := strings.ReplaceAll(name, "-", "_")
		if other, ok := folded[key]; ok {
			return serverError(name, fmt.Sprintf(
				"name differs from %q only by '-' versus '_'; some clients treat them as the same", other))
		}
		folded[key] = name
	}
	return nil
}

// validateName checks a server name. Names become tool prefixes
// ("<name>__<tool>"), so "__" is reserved.
func validateName(name string) error {
	charsetOK := name != "" && strings.IndexFunc(name, isForbiddenNameRune) < 0
	if !charsetOK || strings.Contains(name, "__") || strings.HasPrefix(name, "_") || strings.HasSuffix(name, "_") {
		return errors.New("name must be ASCII letters, digits, '-' or '_', without '__' and without a leading or trailing '_'")
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("name must be at most %d characters: it is part of every tool name", MaxNameLen)
	}
	return nil
}

func isForbiddenNameRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		return false
	}
	return true
}

func checkServerFields(name string, server *ServerConfig) error {
	if err := validateName(name); err != nil {
		return &ServerError{Name: name, Err: err}
	}
	if _, err := server.Transport(); err != nil {
		return &ServerError{Name: name, Err: err}
	}
	if err := checkBannedReferences(name, server); err != nil {
		return err
	}
	return checkReferences(name, server)
}

// hasReference reports whether text holds a well-formed reference. Malformed
// text is left to checkReferences.
func hasReference(text string) bool {
	accounts, _ := interpolate.References(text)
	return len(accounts) > 0
}

// checkBannedReferences rejects references in the fields that must not hold secrets.
func checkBannedReferences(name string, server *ServerConfig) error {
	if server.Command != nil && hasReference(*server.Command) {
		return serverError(name, "'command' must not contain secret references")
	}
	// URLs end up in logs and error messages; secrets belong in 'headers'.
	if server.URL != nil && hasReference(*server.URL) {
		return serverError(name, "'url' must not contain secret references; use 'headers' instead")
	}
	// Arguments are visible to every local process (`ps`); use 'env' instead.
	for _, arg := range server.Args {
		if hasReference(arg) {
			return serverError(name, "'args' must not contain secret references (they show up in `ps`); pass secrets through 'env'")
		}
	}
	return checkExtraFields(name, server.Extra)
}

// checkExtraFields rejects references in fields toolward ignores, where a
// reference would silently go unexpanded.
func checkExtraFields(name string, extra map[string]json.RawMessage) error {
	for _, field := range sortedKeys(extra) {
		if rawContainsReference(extra[field]) {
			return serverError(name, fmt.Sprintf("secret references are not supported in field %q", field))
		}
	}
	return nil
}

// rawContainsReference reports whether a string anywhere inside the JSON value
// holds a "${keychain:" reference.
func rawContainsReference(raw json.RawMessage) bool {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	return valueContainsReference(value)
}

func valueContainsReference(value any) bool {
	switch v := value.(type) {
	case string:
		return strings.Contains(v, "${keychain:")
	case []any:
		for _, item := range v {
			if valueContainsReference(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range v {
			if valueContainsReference(item) {
				return true
			}
		}
	}
	return false
}

// checkReferences parses every interpolated string, so a malformed reference
// fails at load time.
func checkReferences(name string, server *ServerConfig) error {
	for _, text := range server.interpolatedStrings() {
		if _, err := interpolate.References(text); err != nil {
			return &ServerError{Name: name, Err: err}
		}
	}
	return nil
}
