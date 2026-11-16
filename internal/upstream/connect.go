package upstream

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/henry40408/toolward/internal/interpolate"
	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/redact"
	"github.com/henry40408/toolward/internal/store"
)

// Connector opens a connection to an upstream. Errors must never contain
// secret values. The session outlives ctx: ctx only bounds the connecting.
type Connector interface {
	Connect(ctx context.Context, handler *Handler) (*mcpwire.Session, error)
}

// StdioSpec is a stdio server started as a child process.
type StdioSpec struct {
	Command string
	Args    []string
	Env     map[string]string
}

// StdioConnector spawns a child process, expanding ${keychain:...} references
// just before it starts.
type StdioConnector struct {
	Name  string
	Spec  StdioSpec
	Store store.Store
	// Log gets the stderr of the child, with secrets masked. It is piped and
	// never inherited, because agents keep MCP stderr in logs they can read.
	Log io.Writer
}

// BuiltCommand is a child command with its secrets resolved.
type BuiltCommand struct {
	Path string
	Args []string
	// Env is "KEY=value" in key order.
	Env []string
	// Secrets are the values substituted into the command, for redaction.
	Secrets []string
}

// BuildCommand resolves the secrets of spec. The store may show an OS prompt.
func BuildCommand(spec StdioSpec, secretStore store.Store) (BuiltCommand, error) {
	built := BuiltCommand{Path: spec.Command}
	for _, arg := range spec.Args {
		expanded, err := expandInto(&built, arg, secretStore)
		if err != nil {
			return BuiltCommand{}, err
		}
		built.Args = append(built.Args, expanded)
	}
	for _, key := range sortedKeys(spec.Env) {
		expanded, err := expandInto(&built, spec.Env[key], secretStore)
		if err != nil {
			return BuiltCommand{}, err
		}
		built.Env = append(built.Env, key+"="+expanded)
	}
	return built, nil
}

func expandInto(built *BuiltCommand, input string, secretStore store.Store) (string, error) {
	expanded, secrets, err := interpolate.ExpandCollecting(input, secretStore)
	built.Secrets = append(built.Secrets, secrets...)
	return expanded, err
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Connect starts the child and completes the handshake.
func (c *StdioConnector) Connect(ctx context.Context, handler *Handler) (*mcpwire.Session, error) {
	built, err := BuildCommand(c.Spec, c.Store)
	if err != nil {
		return nil, err
	}
	handler.RememberSecrets(built.Secrets)
	transport, err := mcpwire.StartCommand(mcpwire.CommandConfig{
		Path:         built.Path,
		Args:         built.Args,
		ExtraEnv:     built.Env,
		OnStderrLine: c.relayStderr(built.Secrets),
	})
	if err != nil {
		return nil, fmt.Errorf("cannot start %q: %w", c.Spec.Command, err)
	}
	peer := mcpwire.NewPeer(transport, handler)
	session, err := mcpwire.Initialize(ctx, peer, ClientInfo())
	if err != nil {
		_ = peer.Close()
		return nil, handshakeError(err, built.Secrets)
	}
	return session, nil
}

// handshakeError masks the text because the upstream controls it and may echo
// its environment back.
func handshakeError(err error, secrets []string) error {
	return fmt.Errorf("%s", redact.Redact("handshake failed: "+err.Error(), secrets))
}

func (c *StdioConnector) relayStderr(secrets []string) func(string) {
	return func(line string) {
		if c.Log == nil {
			return
		}
		text := strings.ToValidUTF8(strings.TrimRightFunc(line, unicode.IsSpace), "�")
		fmt.Fprintf(c.Log, "[%s] %s\n", c.Name, redact.Redact(text, secrets))
	}
}
