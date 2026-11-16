package oauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/henry40408/toolward/internal/interpolate"
	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/redact"
	"github.com/henry40408/toolward/internal/store"
	"github.com/henry40408/toolward/internal/upstream"
)

// Connector connects to an HTTP server with the tokens that `auth login`
// stored. It never opens a browser.
type Connector struct {
	Server string
	URL    string
	// ClientSecret is the configured secret, unexpanded. Nil means none.
	ClientSecret *string
	Store        store.Store
	Log          io.Writer
	// Clients are the HTTP clients of the OAuth requests. Nil builds them.
	Clients *HTTPClients
}

func (c *Connector) loginHint() error {
	return fmt.Errorf("not logged in: run `toolward auth login %s`", c.Server)
}

func (c *Connector) expiredHint() error {
	return fmt.Errorf("the login has expired: run `toolward auth login %s`", c.Server)
}

// Connect implements upstream.Connector.
func (c *Connector) Connect(ctx context.Context, handler *upstream.Handler) (*mcpwire.Session, error) {
	account, err := AccountFor(c.Server)
	if err != nil {
		return nil, err
	}
	tokens := NewTokenStore(c.Store, account).OnSave(handler.AddSecrets)
	stored, err := tokens.Load()
	if err != nil {
		return nil, err
	}
	if stored == nil || stored.TokenResponse == nil {
		return nil, c.loginHint()
	}
	secret, secrets, err := c.clientSecretFor(stored.ClientID)
	if err != nil {
		return nil, err
	}
	session, err := c.connectWith(ctx, connectRequest{
		handler:     handler,
		tokens:      tokens,
		stored:      stored,
		credentials: ClientCredentials{ClientID: stored.ClientID, ClientSecret: secret},
		secrets:     secrets,
	})
	return session, err
}

type connectRequest struct {
	handler     *upstream.Handler
	tokens      *TokenStore
	stored      *StoredCredentials
	credentials ClientCredentials
	secrets     []string
}

func (c *Connector) connectWith(ctx context.Context, request connectRequest) (*mcpwire.Session, error) {
	base, err := parseServerURL(c.URL)
	if err != nil {
		return nil, err
	}
	clients := c.Clients
	if clients == nil {
		clients = NewHTTPClients(base)
	}
	secrets := request.secrets
	discovery, err := Discover(ctx, base, clients.Stop)
	if err != nil {
		return nil, maskError(err, secrets)
	}
	if issuerChanged(request.stored, discovery) {
		if err := forgetLogin(request.tokens, request.stored); err != nil {
			return nil, maskError(err, secrets)
		}
		return nil, c.loginHint()
	}
	manager := &TokenManager{Tokens: request.tokens, Discovery: discovery, Credentials: request.credentials, Client: clients.Stop}
	token, err := manager.Token(ctx)
	if errors.Is(err, ErrAuthorizationRequired) {
		return nil, c.expiredHint()
	}
	if err != nil {
		return nil, maskError(err, secrets)
	}
	secrets = append(secrets, token)
	secrets, err = withStoredTokens(request.tokens, secrets)
	if err != nil {
		return nil, maskError(err, secrets)
	}
	request.handler.RememberSecrets(secrets)
	session, err := upstream.ConnectHTTP(ctx, mcpwire.HTTPConfig{URL: c.URL, Tokens: manager}, request.handler)
	if err != nil {
		return nil, maskError(fmt.Errorf("handshake failed: %w", err), secrets)
	}
	return session, nil
}

func maskError(err error, secrets []string) error {
	return errors.New(redact.Redact(err.Error(), secrets))
}

// withStoredTokens adds both tokens as they are after any refresh, so that
// neither reaches the agent.
func withStoredTokens(tokens *TokenStore, secrets []string) ([]string, error) {
	current, err := tokens.Load()
	if err != nil || current == nil {
		return secrets, err
	}
	return append(secrets, current.Values()...), nil
}

// clientSecretFor returns the secret to refresh with and every secret to mask.
// A configured secret wins, and the stored client record is read only without
// one.
func (c *Connector) clientSecretFor(tokenClientID string) (*string, []string, error) {
	var secrets []string
	var configured *string
	if c.ClientSecret != nil {
		value, found, err := interpolate.ExpandCollecting(*c.ClientSecret, c.Store)
		secrets = append(secrets, found...)
		if err != nil {
			return nil, nil, maskError(err, secrets)
		}
		configured = &value
	}
	var record *ClientRecord
	if configured == nil {
		record = ReadClientRecordLenient(c.Store, c.Server, c.Log)
	}
	used, mask := ResolveClientSecret(configured, record, tokenClientID)
	return used, append(secrets, mask...), nil
}

// issuerChanged tells whether the tokens came from another authorization
// server than the one the resource names now. Tokens are not sent there.
func issuerChanged(stored *StoredCredentials, discovery *Discovery) bool {
	if stored.Issuer == nil || discovery.Metadata.Issuer == nil {
		return false
	}
	return !sameIssuer(*stored.Issuer, *discovery.Metadata.Issuer)
}

// forgetLogin drops the tokens of the old server. A client id that is an https
// URL is a metadata document, valid at any server, so it is kept.
func forgetLogin(tokens *TokenStore, stored *StoredCredentials) error {
	if !isMetadataDocumentClientID(stored.ClientID) {
		return tokens.Clear()
	}
	return tokens.Save(&StoredCredentials{ClientID: stored.ClientID, GrantedScopes: []string{}})
}

func isMetadataDocumentClientID(clientID string) bool {
	parsed, err := url.Parse(clientID)
	return err == nil && strings.EqualFold(parsed.Scheme, "https") && parsed.Host != "" && parsed.Path != "" && parsed.Path != "/"
}
