package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
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
	request, err := m.refreshRequest(ctx, form)
	if err != nil {
		return nil, fmt.Errorf("OAuth token refresh failed: %w", err)
	}
	answer, err := send(m.Client, request)
	if err != nil {
		return nil, fmt.Errorf("OAuth token refresh failed: %w", err)
	}
	return parseRefresh(answer)
}

func (m *TokenManager) refreshRequest(ctx context.Context, form url.Values) (*http.Request, error) {
	style := authStyle(m.Discovery.Metadata, m.Credentials)
	secret := m.Credentials.ClientSecret
	if secret == nil || style == oauth2.AuthStyleInParams {
		form.Set("client_id", m.Credentials.ClientID)
	}
	if secret != nil && style == oauth2.AuthStyleInParams {
		form.Set("client_secret", *secret)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.Discovery.Metadata.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	if secret != nil && style == oauth2.AuthStyleInHeader {
		request.SetBasicAuth(url.QueryEscape(m.Credentials.ClientID), url.QueryEscape(*secret))
	}
	return request, nil
}

// parseRefresh reads the answer of the token endpoint. invalid_grant means the
// refresh token is no good, which is the end of the login.
func parseRefresh(answer *response) (*TokenResponse, error) {
	if answer.Status >= 200 && answer.Status <= 299 {
		response, err := ParseTokenResponse(answer.Body)
		if err != nil {
			return nil, errors.New("OAuth token refresh failed: Server returned invalid response")
		}
		return &response, nil
	}
	var failure struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(answer.Body, &failure)
	if failure.Error == "invalid_grant" {
		return nil, fmt.Errorf("%w: OAuth refresh token was rejected", ErrAuthorizationRequired)
	}
	return nil, fmt.Errorf("OAuth token refresh failed: Server returned error response (HTTP %d): %s", answer.Status, answer.Body)
}
