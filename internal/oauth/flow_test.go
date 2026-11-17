package oauth

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/config"
	"github.com/henry40408/toolward/internal/store"
	"github.com/henry40408/toolward/internal/upstream"
)

// browserFollowing is a browser that follows the redirect to the callback.
func browserFollowing(t *testing.T) func(string) {
	return func(authURL string) {
		go func() {
			answer, err := http.Get(authURL)
			if err != nil {
				t.Errorf("browser: %v", err)
				return
			}
			_ = answer.Body.Close()
		}()
	}
}

func loginRequest(fake *fakeServer, memory store.Store, oauth config.OAuthConfig) LoginRequest {
	return LoginRequest{
		Server:  "sentry",
		URL:     fake.mcpURL(),
		OAuth:   &oauth,
		Store:   memory,
		Open:    browserFollowing(fake.t),
		Timeout: 10 * time.Second,
	}
}

func loadCredentials(t *testing.T, memory store.Store) *StoredCredentials {
	t.Helper()
	credentials, err := NewTokenStore(memory, "oauth.sentry").Load()
	if err != nil || credentials == nil {
		t.Fatalf("load: %v, %v", credentials, err)
	}
	return credentials
}

func TestLoginRegistersAClientAndStoresTheTokens(t *testing.T) {
	fake := newFakeServer(t)
	memory := store.NewMemory()
	var announced string
	request := loginRequest(fake, memory, config.OAuthConfig{})
	request.Announce = func(authURL string) { announced = authURL }
	if err := Login(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	stored := loadCredentials(t, memory)
	if stored.ClientID != "dynamic-client" || stored.TokenResponse.AccessToken != "access-1" || *stored.TokenResponse.RefreshToken != "refresh-1" {
		t.Fatalf("got %+v", stored)
	}
	if *stored.Issuer != fake.server.URL || !slices.Equal(stored.GrantedScopes, []string{"read"}) || stored.TokenReceivedAt == nil {
		t.Fatalf("got %+v", stored)
	}
	if !strings.HasPrefix(announced, fake.server.URL+"/authorize?") {
		t.Fatalf("announced %q", announced)
	}
	body := fake.registered[0]
	if body["client_name"] != "toolward" || body["token_endpoint_auth_method"] != "none" || body["application_type"] != "native" || body["scope"] != "read" {
		t.Fatalf("registration %v", body)
	}
	if _, found, _ := memory.Get("oauth-client.sentry"); found {
		t.Fatal("a public client needs no client record")
	}
	if fake.tokenRequests[0].Get("resource") != fake.mcpURL() || fake.tokenAuth[0] != "" || fake.tokenRequests[0].Get("client_id") != "dynamic-client" {
		t.Fatalf("token request %v %q", fake.tokenRequests[0], fake.tokenAuth[0])
	}
}

func TestLoginWithAPreregisteredClientAuthenticatesWithItsSecret(t *testing.T) {
	fake := newFakeServer(t)
	memory := store.NewMemoryWith(map[string]string{"pre.secret": "s3cret"})
	id, secret := "pre-id", "${keychain:pre.secret}"
	request := loginRequest(fake, memory, config.OAuthConfig{ClientID: &id, ClientSecret: &secret})
	if err := Login(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(fake.registered) != 0 {
		t.Fatal("a preregistered client is not registered again")
	}
	if loadCredentials(t, memory).ClientID != "pre-id" {
		t.Fatal("wrong client id")
	}
	user, password, _ := (&http.Request{Header: http.Header{"Authorization": {fake.tokenAuth[0]}}}).BasicAuth()
	if user != "pre-id" || password != "s3cret" {
		t.Fatalf("basic auth %q %q", user, password)
	}
}

func TestLoginTimesOutWithoutTheBrowser(t *testing.T) {
	fake := newFakeServer(t)
	request := loginRequest(fake, store.NewMemory(), config.OAuthConfig{})
	request.Open = nil
	request.Timeout = time.Second
	err := Login(context.Background(), request)
	if err == nil || err.Error() != "no authorization within 1 seconds" {
		t.Fatalf("got %v", err)
	}
}

func TestLoginErrorsNeverShowAConfiguredSecret(t *testing.T) {
	fake := newFakeServer(t)
	memory := store.NewMemoryWith(map[string]string{"pre.secret": "s3cret"})
	id, secret := "pre-id", "${keychain:pre.secret}"
	request := loginRequest(fake, memory, config.OAuthConfig{ClientID: &id, ClientSecret: &secret})
	request.URL = fake.server.URL + "/other?token=s3cret"
	err := Login(context.Background(), request)
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginWithAnInvalidServerNameFails(t *testing.T) {
	fake := newFakeServer(t)
	request := loginRequest(fake, store.NewMemory(), config.OAuthConfig{})
	request.Server = "bad name!"
	if err := Login(context.Background(), request); err == nil {
		t.Fatal("expected an error")
	}
}

func connectorFor(fake *fakeServer, memory store.Store) *Connector {
	return &Connector{Server: "sentry", URL: fake.mcpURL(), Store: memory}
}

func loggedIn(t *testing.T, fake *fakeServer) *store.Memory {
	t.Helper()
	memory := store.NewMemory()
	if err := Login(context.Background(), loginRequest(fake, memory, config.OAuthConfig{})); err != nil {
		t.Fatal(err)
	}
	return memory
}

func TestConnectorSendsTheStoredToken(t *testing.T) {
	fake := newFakeServer(t)
	memory := loggedIn(t, fake)
	handler := &upstream.Handler{}
	session, err := connectorFor(fake, memory).Connect(context.Background(), handler)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Peer.Close()
	if fake.lastBearer() != "Bearer access-1" {
		t.Fatalf("bearer %q", fake.lastBearer())
	}
	secrets := handler.Secrets()
	if !slices.Contains(secrets, "access-1") || !slices.Contains(secrets, "refresh-1") {
		t.Fatalf("secrets %v", secrets)
	}
}

func TestConnectorWithoutALoginSaysSo(t *testing.T) {
	fake := newFakeServer(t)
	_, err := connectorFor(fake, store.NewMemory()).Connect(context.Background(), &upstream.Handler{})
	if err == nil || err.Error() != "not logged in: run `toolward auth login sentry`" {
		t.Fatalf("got %v", err)
	}
}

func expire(t *testing.T, memory store.Store) {
	t.Helper()
	tokens := NewTokenStore(memory, "oauth.sentry")
	stored := loadCredentials(t, memory)
	long := uint64(1)
	stored.TokenReceivedAt = &long
	if err := tokens.Save(stored); err != nil {
		t.Fatal(err)
	}
}

func TestConnectorRefreshesAnExpiredToken(t *testing.T) {
	fake := newFakeServer(t)
	memory := loggedIn(t, fake)
	expire(t, memory)
	handler := &upstream.Handler{}
	session, err := connectorFor(fake, memory).Connect(context.Background(), handler)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Peer.Close()
	refresh := fake.tokenRequests[len(fake.tokenRequests)-1]
	if refresh.Get("grant_type") != "refresh_token" || refresh.Get("refresh_token") != "refresh-1" || refresh.Get("resource") != fake.mcpURL() || refresh.Get("scope") != "read" {
		t.Fatalf("refresh request %v", refresh)
	}
	stored := loadCredentials(t, memory)
	if stored.TokenResponse.AccessToken != "access-2" || *stored.TokenResponse.RefreshToken != "refresh-2" || *stored.TokenReceivedAt < 1_000_000 {
		t.Fatalf("got %+v", stored)
	}
	if fake.lastBearer() != "Bearer access-2" {
		t.Fatalf("bearer %q", fake.lastBearer())
	}
	if !slices.Contains(handler.Secrets(), "refresh-2") {
		t.Fatalf("secrets %v", handler.Secrets())
	}
}

func TestARefreshWithoutANewRefreshTokenKeepsTheOldOne(t *testing.T) {
	fake := newFakeServer(t)
	memory := loggedIn(t, fake)
	expire(t, memory)
	fake.refreshGrant = "reuse"
	session, err := connectorFor(fake, memory).Connect(context.Background(), &upstream.Handler{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Peer.Close()
	if *loadCredentials(t, memory).TokenResponse.RefreshToken != "refresh-1" {
		t.Fatal("the refresh token was lost")
	}
}

func TestARejectedRefreshMeansTheLoginExpired(t *testing.T) {
	fake := newFakeServer(t)
	memory := loggedIn(t, fake)
	expire(t, memory)
	fake.refreshGrant = "invalid_grant"
	_, err := connectorFor(fake, memory).Connect(context.Background(), &upstream.Handler{})
	if err == nil || err.Error() != "the login has expired: run `toolward auth login sentry`" {
		t.Fatalf("got %v", err)
	}
}

func TestATokenOfAnotherClientIsNotRefreshed(t *testing.T) {
	fake := newFakeServer(t)
	memory := loggedIn(t, fake)
	expire(t, memory)
	connector := connectorFor(fake, memory)
	stored := loadCredentials(t, memory)
	stored.ClientID = "someone-else"
	_ = NewTokenStore(memory, "oauth.sentry").Save(stored)
	secret := "other"
	connector.ClientSecret = &secret
	manager := &TokenManager{
		Tokens:      NewTokenStore(memory, "oauth.sentry"),
		Discovery:   &Discovery{Metadata: legacyMetadata(mustParse(t, fake.mcpURL())), Resource: fake.mcpURL()},
		Credentials: ClientCredentials{ClientID: "dynamic-client"},
		Client:      http.DefaultClient,
	}
	if _, err := manager.Token(context.Background()); err == nil || err.Error() != ErrAuthorizationRequired.Error() {
		t.Fatalf("got %v", err)
	}
}

func TestAChangedIssuerForgetsTheLogin(t *testing.T) {
	fake := newFakeServer(t)
	memory := loggedIn(t, fake)
	fake.mu.Lock()
	fake.issuerOverride = fake.server.URL
	fake.mu.Unlock()
	stored := loadCredentials(t, memory)
	other := "https://old.example"
	stored.Issuer = &other
	_ = NewTokenStore(memory, "oauth.sentry").Save(stored)
	_, err := connectorFor(fake, memory).Connect(context.Background(), &upstream.Handler{})
	if err == nil || !strings.HasPrefix(err.Error(), "not logged in") {
		t.Fatalf("got %v", err)
	}
	if _, found, _ := memory.Get("oauth.sentry"); found {
		t.Fatal("the tokens of the old server stay")
	}
}

func TestAChangedIssuerKeepsAMetadataDocumentClientID(t *testing.T) {
	fake := newFakeServer(t)
	memory := loggedIn(t, fake)
	stored := loadCredentials(t, memory)
	stored.ClientID = "https://client.example/metadata.json"
	other := "https://old.example"
	stored.Issuer = &other
	_ = NewTokenStore(memory, "oauth.sentry").Save(stored)
	if _, err := connectorFor(fake, memory).Connect(context.Background(), &upstream.Handler{}); err == nil {
		t.Fatal("expected an error")
	}
	kept := loadCredentials(t, memory)
	if kept.TokenResponse != nil || kept.ClientID != "https://client.example/metadata.json" {
		t.Fatalf("got %+v", kept)
	}
}
