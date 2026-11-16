package upstream

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/henry40408/toolward/internal/interpolate"
	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/store"
)

// HTTPSpec is a streamable HTTP server.
type HTTPSpec struct {
	URL     string
	Headers map[string]string
}

// HTTPConnector connects to a URL, expanding ${keychain:...} references in
// the headers just before the request is made.
type HTTPConnector struct {
	Spec  HTTPSpec
	Store store.Store
	// Client is the HTTP client. Nil gives the safe default of mcpwire.
	Client *http.Client
}

// BuiltHeaders are headers with their secrets resolved.
type BuiltHeaders struct {
	Header http.Header
	// Secrets are the values substituted into the headers, for redaction.
	Secrets []string
}

// BuildHeaders resolves the secrets of the headers. The store may show an OS
// prompt. Error text never contains a header value.
func BuildHeaders(headers map[string]string, secretStore store.Store) (BuiltHeaders, error) {
	built := BuiltHeaders{Header: http.Header{}}
	for _, key := range sortedKeys(headers) {
		if err := addHeader(&built, key, headers[key], secretStore); err != nil {
			return BuiltHeaders{}, err
		}
	}
	return built, nil
}

func addHeader(built *BuiltHeaders, key, value string, secretStore store.Store) error {
	if !validHeaderName(key) {
		return fmt.Errorf("invalid header name %q", key)
	}
	expanded, secrets, err := interpolate.ExpandCollecting(value, secretStore)
	built.Secrets = append(built.Secrets, secrets...)
	if err != nil {
		return err
	}
	if !validHeaderValue(expanded) {
		return fmt.Errorf("invalid value for header %q", key)
	}
	canonical := http.CanonicalHeaderKey(key)
	if _, set := built.Header[canonical]; set {
		return fmt.Errorf("header %q is set twice (names ignore case)", key)
	}
	built.Header[canonical] = []string{expanded}
	return nil
}

// validHeaderName accepts the token characters of RFC 9110.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, char := range name {
		if !isTokenChar(char) {
			return false
		}
	}
	return true
}

func isTokenChar(char rune) bool {
	switch {
	case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", char)
}

// validHeaderValue rejects control characters other than tab, and DEL.
func validHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		char := value[i]
		if char != '\t' && (char < 0x20 || char == 0x7f) {
			return false
		}
	}
	return true
}

// Connect opens the connection with the headers resolved just now.
func (c *HTTPConnector) Connect(ctx context.Context, handler *Handler) (*mcpwire.Session, error) {
	built, err := BuildHeaders(c.Spec.Headers, c.Store)
	if err != nil {
		return nil, err
	}
	handler.RememberSecrets(built.Secrets)
	config := mcpwire.HTTPConfig{URL: c.Spec.URL, Headers: built.Header, Client: c.Client}
	session, err := ConnectHTTP(ctx, config, handler)
	if err != nil {
		return nil, handshakeError(err, built.Secrets)
	}
	return session, nil
}

// ConnectHTTP connects with the stateless protocol (server/discover) and falls
// back to the initialize handshake when the server does not answer it, so
// both old and new servers work.
//
// Any failure that is not about authorization is retried once with the plain
// handshake on a fresh transport, because a server that is older than the
// probe may answer it with a 5xx, an HTML page, or a 401 without a challenge.
// The error of that retry is returned.
func ConnectHTTP(ctx context.Context, config mcpwire.HTTPConfig, handler *Handler) (*mcpwire.Session, error) {
	session, err := connectOnce(ctx, config, handler, mcpwire.Discover)
	if err == nil || mcpwire.IsAuthorizationRequired(err) {
		return session, err
	}
	return connectOnce(ctx, config, handler, mcpwire.Initialize)
}

type connectFunc func(context.Context, *mcpwire.Peer, mcpwire.Implementation) (*mcpwire.Session, error)

func connectOnce(ctx context.Context, config mcpwire.HTTPConfig, handler *Handler, connect connectFunc) (*mcpwire.Session, error) {
	peer := mcpwire.NewPeer(mcpwire.NewHTTPTransport(config), handler)
	session, err := connect(ctx, peer, ClientInfo())
	if err != nil {
		_ = peer.Close()
		return nil, err
	}
	return session, nil
}
