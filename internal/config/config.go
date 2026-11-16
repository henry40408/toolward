// Package config reads the config file: a JSON(C) document using the de facto
// "mcpServers" layout that Claude Code, Cursor, Claude Desktop and others
// share, so existing entries can be pasted in and their secrets replaced with
// "${keychain:<account>}".
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/tailscale/hujson"
)

// ErrEmpty means the config file holds no document.
var ErrEmpty = errors.New("config file is empty")

// Config is the parsed and validated config file.
type Config struct {
	Servers map[string]*ServerConfig
}

// ServerConfig is one entry of "mcpServers".
type ServerConfig struct {
	Kind    *string
	Command *string
	Args    []string
	Env     map[string]string
	URL     *string
	Headers map[string]string
	OAuth   *OAuthConfig
	// Extra holds fields toolward does not use ("disabled", "timeout", ...).
	// They are kept, not rejected.
	Extra map[string]json.RawMessage
}

// OAuthConfig is the "oauth" setting of an http server.
type OAuthConfig struct {
	Scopes       []string
	ClientID     *string
	ClientSecret *string
	// CallbackPort is a fixed port for the login redirect; default is a random one.
	CallbackPort *uint16
}

// Names returns the server names, sorted.
func (c *Config) Names() []string {
	return slices.Sorted(maps.Keys(c.Servers))
}

// Parse parses and validates config text.
func Parse(text string) (*Config, error) {
	standard, err := standardize(text)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(standard), []byte("null")) {
		return nil, ErrEmpty
	}
	config, err := decode(standard)
	if err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return config, nil
}

// standardize turns JSONC into plain JSON.
func standardize(text string) ([]byte, error) {
	standard, err := hujson.Standardize([]byte(text))
	if err == nil {
		return standard, nil
	}
	if isBlank(text) {
		return nil, ErrEmpty
	}
	return nil, syntaxError(err)
}

var errorPosition = regexp.MustCompile(`^hujson: line (\d+), column (\d+):`)

// syntaxError reports only where the syntax error is. The parser's own text
// quotes the input, and the config may already hold a literal secret.
func syntaxError(err error) error {
	match := errorPosition.FindStringSubmatch(err.Error())
	if match == nil {
		return errors.New("invalid JSON")
	}
	return fmt.Errorf("invalid JSON on line %s column %s", match[1], match[2])
}

// isBlank reports whether text holds nothing but whitespace and comments.
func isBlank(text string) bool {
	value, err := hujson.Parse([]byte("[" + text + "\n]"))
	if err != nil {
		return false
	}
	array, ok := value.Value.(*hujson.Array)
	return ok && len(array.Elements) == 0
}

// Load reads and parses the config file at path.
func Load(path string) (*Config, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", path, unwrapPathError(err))
	}
	return Parse(string(text))
}

func unwrapPathError(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}

// DefaultPath returns ~/.config/toolward/config.json (XDG layout on macOS and
// Linux). An absolute XDG_CONFIG_HOME wins.
func DefaultPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if filepath.IsAbs(dir) {
		return filepath.Join(dir, "toolward", "config.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine the config directory: %v", err)
	}
	return filepath.Join(home, ".config", "toolward", "config.json"), nil
}
