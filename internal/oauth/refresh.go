package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// refreshBuffer is how long before expiry a token is refreshed, so that it
// does not run out between being handed out and being used.
const refreshBuffer = 30 * time.Second

// ErrAuthorizationRequired means the stored login cannot give a token any
// more, and the user has to log in again.
var ErrAuthorizationRequired = errors.New("OAuth authorization required")

// TokenManager hands out the access token of a stored login and refreshes it
// when it is about to expire. It never opens a browser.
type TokenManager struct {
	Tokens      *TokenStore
	Discovery   *Discovery
	Credentials ClientCredentials
	// Client sends the refresh request. It must not follow redirects.
	Client *http.Client
	// Now is the clock. Nil is the real one.
	Now func() time.Time
}

func (m *TokenManager) now() time.Time {
	if m.Now == nil {
		return time.Now()
	}
	return m.Now()
}

// Token returns a token that is valid for at least 30 seconds, or
// ErrAuthorizationRequired when the login is over. A record that has no
// expiry information is used as it is.
func (m *TokenManager) Token(ctx context.Context) (string, error) {
	stored, err := m.Tokens.Load()
	if err != nil {
		return "", err
	}
	if stored == nil || stored.TokenResponse == nil {
		return "", ErrAuthorizationRequired
	}
	if !m.needsRefresh(stored) {
		return stored.TokenResponse.AccessToken, nil
	}
	refreshed, err := m.refresh(ctx)
	if err != nil {
		return "", err
	}
	return refreshed.AccessToken, nil
}

func (m *TokenManager) needsRefresh(stored *StoredCredentials) bool {
	response := stored.TokenResponse
	if response.ExpiresIn == nil || stored.TokenReceivedAt == nil {
		return false
	}
	received := time.Unix(int64(*stored.TokenReceivedAt), 0)
	remaining := time.Duration(*response.ExpiresIn)*time.Second - max(m.now().Sub(received), 0)
	return remaining < refreshBuffer
}

// refresh exchanges the refresh token. It loads, asks and saves under the
// lock, so that two refreshes do not spend the same refresh token.
func (m *TokenManager) refresh(ctx context.Context) (*TokenResponse, error) {
	defer m.Tokens.LockRefresh()()
	stored, err := m.Tokens.Load()
	if err != nil {
		return nil, err
	}
	refreshToken, err := m.refreshTokenOf(stored)
	if err != nil {
		return nil, err
	}
	response, err := m.requestRefresh(ctx, refreshToken, stored.GrantedScopes)
	if err != nil {
		return nil, err
	}
	// A refresh may leave out the refresh token. The old one stays valid then.
	if response.RefreshToken == nil {
		response.RefreshToken = &refreshToken
	}
	granted := stored.GrantedScopes
	if response.Scopes != nil {
		granted = response.Scopes
	}
	saved := &StoredCredentials{
		ClientID:        m.Credentials.ClientID,
		TokenResponse:   response,
		GrantedScopes:   nonNil(granted),
		TokenReceivedAt: unixNow(m.now()),
		Issuer:          m.Discovery.Metadata.Issuer,
	}
	if err := m.Tokens.Save(saved); err != nil {
		return nil, err
	}
	return response, nil
}

// refreshTokenOf is the refresh token to spend. The record of another client
// is not used: its token would be sent as this client.
func (m *TokenManager) refreshTokenOf(stored *StoredCredentials) (string, error) {
	if stored == nil || stored.TokenResponse == nil || stored.ClientID != m.Credentials.ClientID {
		return "", ErrAuthorizationRequired
	}
	if stored.TokenResponse.RefreshToken == nil {
		return "", ErrAuthorizationRequired
	}
	return *stored.TokenResponse.RefreshToken, nil
}

func (m *TokenManager) requestRefresh(ctx context.Context, refreshToken string, scopes []string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		// RFC 8707 asks for the resource on refreshes too.
		"resource": {m.Discovery.Resource},
	}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	response, err := requestTokens(ctx, m.Client, tokenRequest{
		Metadata:    m.Discovery.Metadata,
		Credentials: m.Credentials,
		Form:        form,
		Action:      "refresh",
	})
	if errors.Is(err, errInvalidGrant) {
		return nil, fmt.Errorf("%w: OAuth refresh token was rejected", ErrAuthorizationRequired)
	}
	return response, err
}
