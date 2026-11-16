package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"golang.org/x/oauth2"
)

// ClientCredentials identify toolward to the authorization server.
type ClientCredentials struct {
	ClientID string
	// ClientSecret is nil for a public client.
	ClientSecret *string
}

// authStyle picks where the client authenticates at the token endpoint. A
// secret goes in the Authorization header unless the server accepts only the
// request body. A public client sends its id in the body.
func authStyle(metadata AuthorizationMetadata, credentials ClientCredentials) oauth2.AuthStyle {
	if credentials.ClientSecret == nil {
		return oauth2.AuthStyleInParams
	}
	if contains(metadata.TokenAuthMethods, "client_secret_post") && !contains(metadata.TokenAuthMethods, "client_secret_basic") {
		return oauth2.AuthStyleInParams
	}
	return oauth2.AuthStyleInHeader
}

func oauth2Config(metadata AuthorizationMetadata, credentials ClientCredentials, redirectURI string) *oauth2.Config {
	config := &oauth2.Config{
		ClientID:    credentials.ClientID,
		RedirectURL: redirectURI,
		Endpoint: oauth2.Endpoint{
			AuthURL:   metadata.AuthorizationEndpoint,
			TokenURL:  metadata.TokenEndpoint,
			AuthStyle: authStyle(metadata, credentials),
		},
	}
	if credentials.ClientSecret != nil {
		config.ClientSecret = *credentials.ClientSecret
	}
	return config
}

// Authorization is one authorization request on its way: the URL for the
// user, and what is needed to finish it.
type Authorization struct {
	URL      *url.URL
	State    string
	verifier string
	config   *oauth2.Config
	request  AuthorizationRequest
}

// AuthorizationRequest is everything the authorization request depends on.
type AuthorizationRequest struct {
	Discovery   *Discovery
	Credentials ClientCredentials
	RedirectURI string
	Scopes      []string
}

// StartAuthorization builds the URL the user is sent to. It has a random state
// and an S256 PKCE challenge, and names the resource (RFC 8707).
func StartAuthorization(request AuthorizationRequest) (*Authorization, error) {
	if err := request.Discovery.Metadata.ValidateForCodeFlow(); err != nil {
		return nil, err
	}
	config := oauth2Config(request.Discovery.Metadata, request.Credentials, request.RedirectURI)
	config.Scopes = request.Scopes
	verifier := oauth2.GenerateVerifier()
	state := oauth2.GenerateVerifier()
	raw := config.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("resource", request.Discovery.Resource))
	authURL, err := ValidatedAuthURL(raw)
	if err != nil {
		return nil, err
	}
	// An authorization_endpoint that has its own state in the query would
	// win over ours. Then the redirect could not be tied to this request.
	if urlState, err := AuthURLState(authURL); err != nil || urlState != state {
		return nil, errors.New("the server's authorization endpoint sets its own state")
	}
	return &Authorization{URL: authURL, State: state, verifier: verifier, config: config, request: request}, nil
}

// Callback is what the redirect of the browser carried.
type callbackParameters struct {
	code   string
	state  string
	issuer *string
}

func parseRedirect(redirect string) (callbackParameters, error) {
	parsed, err := url.Parse(redirect)
	if err != nil {
		return callbackParameters{}, errors.New("URL parse error")
	}
	query := parsed.Query()
	if !query.Has("code") {
		return callbackParameters{}, errors.New("OAuth authorization failed: Authorization callback missing code")
	}
	if !query.Has("state") {
		return callbackParameters{}, errors.New("OAuth authorization failed: Authorization callback missing state")
	}
	parameters := callbackParameters{code: query.Get("code"), state: query.Get("state")}
	if query.Has("iss") {
		issuer := query.Get("iss")
		parameters.issuer = &issuer
	}
	return parameters, nil
}

// validateIssuer binds the redirect to the authorization server (RFC 9207).
func validateIssuer(metadata AuthorizationMetadata, received *string) error {
	if metadata.Issuer == nil {
		if received != nil || metadata.IssuerInResponse {
			return errors.New("OAuth authorization failed: Authorization callback issuer cannot be validated because expected issuer was not recorded")
		}
		return nil
	}
	if received == nil {
		if metadata.IssuerInResponse {
			return fmt.Errorf("Authorization server response missing required issuer: expected %s", *metadata.Issuer)
		}
		return nil
	}
	if *received != *metadata.Issuer {
		return fmt.Errorf("Authorization server issuer mismatch: expected %s, received %s", *metadata.Issuer, *received)
	}
	return nil
}

// Complete exchanges the code of the redirect for tokens. The client sends the
// PKCE verifier and the resource.
func (a *Authorization) Complete(ctx context.Context, client *http.Client, redirect string) (*StoredCredentials, error) {
	parameters, err := parseRedirect(redirect)
	if err != nil {
		return nil, err
	}
	if parameters.state != a.State {
		return nil, errors.New("Internal error: Authorization state not found")
	}
	metadata := a.request.Discovery.Metadata
	if err := validateIssuer(metadata, parameters.issuer); err != nil {
		return nil, err
	}
	response, err := requestTokens(ctx, client, tokenRequest{
		Metadata:    metadata,
		Credentials: a.request.Credentials,
		Form: url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {parameters.code},
			"redirect_uri":  {a.request.RedirectURI},
			"code_verifier": {a.verifier},
			"resource":      {a.request.Discovery.Resource},
		},
		Action: "exchange",
	})
	if err != nil {
		return nil, err
	}
	return a.credentialsFor(response), nil
}

func (a *Authorization) credentialsFor(response *TokenResponse) *StoredCredentials {
	granted := slices.Clone(a.request.Scopes)
	if response.Scopes != nil {
		granted = response.Scopes
	}
	return &StoredCredentials{
		ClientID:        a.request.Credentials.ClientID,
		TokenResponse:   response,
		GrantedScopes:   nonNil(granted),
		TokenReceivedAt: unixNow(time.Now()),
		Issuer:          a.request.Discovery.Metadata.Issuer,
	}
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func unixNow(now time.Time) *uint64 {
	seconds := uint64(max(now.Unix(), 0))
	return &seconds
}
