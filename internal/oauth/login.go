package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/henry40408/toolward/internal/config"
	"github.com/henry40408/toolward/internal/interpolate"
	"github.com/henry40408/toolward/internal/redact"
	"github.com/henry40408/toolward/internal/store"
)

// LoginTimeout is how long `auth login` waits for the user.
const LoginTimeout = 300 * time.Second

// LoginRequest is everything `auth login` needs to know about a server.
type LoginRequest struct {
	Server string
	URL    string
	OAuth  *config.OAuthConfig
	Store  store.Store
	// Announce receives the authorization URL, which holds no secret, for
	// users whose browser did not open.
	Announce func(authURL string)
	// Open opens the URL in the browser. Nil opens nothing.
	Open func(authURL string)
	// Timeout is the wait for the redirect. Zero means LoginTimeout.
	Timeout time.Duration
	// Clients are the HTTP clients of the OAuth requests. Nil builds them.
	Clients *HTTPClients
}

// OpenBrowser opens the system browser. A failure is fine: the URL is shown as
// well.
func OpenBrowser(authURL string) {
	program := "xdg-open"
	if runtime.GOOS == "darwin" {
		program = "open"
	}
	command := exec.Command(program, authURL)
	if command.Start() == nil {
		go func() { _ = command.Wait() }()
	}
}

// Login runs the browser flow and stores the tokens.
func Login(ctx context.Context, request LoginRequest) error {
	flow := &loginFlow{request: request}
	err := flow.run(ctx)
	if err == nil {
		return nil
	}
	return flow.masked(err)
}

// loginFlow holds what a login learns on the way. masks are the secrets that
// error text must not show.
type loginFlow struct {
	request LoginRequest
	masks   []string
}

func (f *loginFlow) masked(err error) error {
	return errors.New(redact.Redact(err.Error(), f.masks))
}

func (f *loginFlow) run(ctx context.Context) error {
	account, err := AccountFor(f.request.Server)
	if err != nil {
		return err
	}
	clientSecret, clientID, err := f.configuredClient()
	if err != nil {
		return err
	}
	// Bind first: the redirect URI must be known before registration.
	callback, err := ListenCallback(callbackPortOf(f.request.OAuth))
	if err != nil {
		return err
	}
	defer callback.Close()
	discovery, clients, err := f.discover(ctx)
	if err != nil {
		return err
	}
	scopes := EffectiveScopes(f.request.OAuth.Scopes, discovery.Hints)
	credentials, registered, err := f.chooseClient(ctx, clients, discovery, ClientCredentials{ClientID: derefOr(clientID), ClientSecret: clientSecret}, RegistrationRequest{
		RedirectURI: callback.RedirectURI(),
		Scopes:      scopes,
	}, clientID != nil)
	if err != nil {
		return err
	}
	authorization, err := StartAuthorization(AuthorizationRequest{
		Discovery:   discovery,
		Credentials: credentials,
		RedirectURI: callback.RedirectURI(),
		Scopes:      scopes,
	})
	if err != nil {
		return err
	}
	redirect, err := f.waitForUser(ctx, callback, authorization)
	if err != nil {
		return err
	}
	saved, err := authorization.Complete(ctx, clients.Stop, redirect)
	if err != nil {
		return err
	}
	if err := NewTokenStore(f.request.Store, account).Save(saved); err != nil {
		return err
	}
	// Only now, with the new tokens saved, may the client record change.
	if err := WriteClientRecord(f.request.Store, f.request.Server, registered); err != nil {
		return fmt.Errorf("the tokens were saved, but the OAuth client record could not be written: run `toolward auth login %s` again", f.request.Server)
	}
	return nil
}

func callbackPortOf(oauth *config.OAuthConfig) uint16 {
	if oauth.CallbackPort == nil {
		return 0
	}
	return *oauth.CallbackPort
}

func derefOr(text *string) string {
	if text == nil {
		return ""
	}
	return *text
}

// configuredClient expands the client secret and id of the config.
func (f *loginFlow) configuredClient() (secret, id *string, err error) {
	secret, err = f.expandOptional(f.request.OAuth.ClientSecret)
	if err != nil {
		return nil, nil, err
	}
	id, err = f.expandOptional(f.request.OAuth.ClientID)
	return secret, id, err
}

// expandOptional expands the references in text, when there is some, and masks
// every secret that went in.
func (f *loginFlow) expandOptional(text *string) (*string, error) {
	if text == nil {
		return nil, nil
	}
	value, secrets, err := interpolate.ExpandCollecting(*text, f.request.Store)
	f.masks = append(f.masks, secrets...)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func (f *loginFlow) discover(ctx context.Context) (*Discovery, *HTTPClients, error) {
	base, err := parseServerURL(f.request.URL)
	if err != nil {
		return nil, nil, err
	}
	clients := f.request.Clients
	if clients == nil {
		clients = NewHTTPClients(base)
	}
	discovery, err := Discover(ctx, base, clients.Stop)
	return discovery, clients, err
}

func parseServerURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || !isHTTPURL(parsed) {
		return nil, errors.New("OAuth error: the server URL is not a valid http(s) URL")
	}
	return parsed, nil
}

// chooseClient builds the client of the request: the configured one when
// there is one, else one registered here. It also returns the client record
// that `serve` needs when the server issued a secret. The session of rmcp
// would drop that secret, so registration is done here.
func (f *loginFlow) chooseClient(ctx context.Context, clients *HTTPClients, discovery *Discovery, configured ClientCredentials, registration RegistrationRequest, preregistered bool) (ClientCredentials, *ClientRecord, error) {
	if preregistered {
		return configured, nil, nil
	}
	registered, err := Register(ctx, clients.Follow, discovery.Metadata, registration)
	if err != nil {
		return ClientCredentials{}, nil, err
	}
	if registered.ClientSecret != nil {
		f.masks = append(f.masks, *registered.ClientSecret)
	}
	credentials := ClientCredentials{ClientID: registered.ClientID, ClientSecret: registered.ClientSecret}
	return credentials, RegistrationRecord(registered.ClientID, registered.ClientSecret), nil
}

// waitForUser shows the URL and waits for the redirect of the browser.
func (f *loginFlow) waitForUser(ctx context.Context, callback *Callback, authorization *Authorization) (string, error) {
	state, err := AuthURLState(authorization.URL)
	if err != nil {
		return "", err
	}
	authorization.State = state
	if f.request.Announce != nil {
		f.request.Announce(authorization.URL.String())
	}
	if f.request.Open != nil {
		f.request.Open(authorization.URL.String())
	}
	timeout := f.request.Timeout
	if timeout == 0 {
		timeout = LoginTimeout
	}
	waitContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	redirect, err := callback.Wait(waitContext, state)
	if errors.Is(waitContext.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		return "", fmt.Errorf("no authorization within %d seconds", int(timeout.Seconds()))
	}
	return redirect, err
}
