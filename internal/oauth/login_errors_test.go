package oauth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/config"
	"github.com/henry40408/toolward/internal/store"
)

func loginWithoutBrowser(t *testing.T, request LoginRequest) error {
	t.Helper()
	request.Open = nil
	request.Timeout = 5 * time.Second
	return Login(context.Background(), request)
}

func TestLoginRefusesAServerURLThatIsNotHTTP(t *testing.T) {
	fake := newFakeServer(t)
	for _, raw := range []string{"ftp://example.com/mcp", "not a url", "http://", "%zz"} {
		request := loginRequest(fake, store.NewMemory(), config.OAuthConfig{})
		request.URL = raw
		err := Login(context.Background(), request)
		if err == nil || err.Error() != "OAuth error: the server URL is not a valid http(s) URL" {
			t.Fatalf("%q: got %v", raw, err)
		}
	}
}

func TestLoginStopsOnAnUnknownKeychainReferenceInTheConfig(t *testing.T) {
	fake := newFakeServer(t)
	secret := "${keychain:missing.secret}"
	request := loginRequest(fake, store.NewMemory(), config.OAuthConfig{ClientSecret: &secret})
	err := Login(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "missing.secret") {
		t.Fatalf("got %v", err)
	}

	id := "${keychain:missing.id}"
	request = loginRequest(fake, store.NewMemory(), config.OAuthConfig{ClientID: &id})
	err = Login(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "missing.id") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginFailsWhenTheCallbackPortIsTaken(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	fake := newFakeServer(t)
	request := loginRequest(fake, store.NewMemory(), config.OAuthConfig{CallbackPort: &port})
	err = Login(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "cannot listen on 127.0.0.1:") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginStoresNothingWhenDiscoveryFails(t *testing.T) {
	server := serveRoutes(t, routes{"/mcp": rawRoute(500, "", "")})
	memory := store.NewMemory()
	request := LoginRequest{Server: "sentry", URL: server.URL + "/mcp", OAuth: &config.OAuthConfig{}, Store: memory}
	err := loginWithoutBrowser(t, request)
	if err == nil || !strings.Contains(err.Error(), "OAuth metadata discovery failed") {
		t.Fatalf("got %v", err)
	}
	if _, found, _ := memory.Get("oauth.sentry"); found {
		t.Fatal("no tokens may be stored")
	}
}

// metadataOnlyServer serves authorization metadata, with extra fields, and
// nothing else.
func metadataOnlyServer(t *testing.T, extra map[string]any) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = serveRoutes(t, routes{
		"/.well-known/oauth-authorization-server": func(w http.ResponseWriter, _ *http.Request) {
			document := authMetadata(server, server.URL)
			for key, value := range extra {
				document[key] = value
			}
			writeJSON(w, 200, document)
		},
	})
	return server
}

func TestLoginFailsWhenTheServerCannotRegisterAClient(t *testing.T) {
	server := metadataOnlyServer(t, nil)
	memory := store.NewMemory()
	request := LoginRequest{Server: "sentry", URL: server.URL + "/mcp", OAuth: &config.OAuthConfig{}, Store: memory}
	if err := loginWithoutBrowser(t, request); err == nil {
		t.Fatal("expected a registration error")
	}
	if _, found, _ := memory.Get("oauth-client.sentry"); found {
		t.Fatal("no client record may be stored")
	}
}

func TestLoginRefusesAServerWithoutTheCodeFlow(t *testing.T) {
	server := metadataOnlyServer(t, map[string]any{"code_challenge_methods_supported": []string{"plain"}})
	id := "client"
	request := LoginRequest{Server: "sentry", URL: server.URL + "/mcp", OAuth: &config.OAuthConfig{ClientID: &id}, Store: store.NewMemory()}
	err := loginWithoutBrowser(t, request)
	if err == nil || !strings.Contains(err.Error(), "PKCE code challenge method (S256)") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginStopsWhenTheContextIsCanceledWhileWaiting(t *testing.T) {
	fake := newFakeServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	request := loginRequest(fake, store.NewMemory(), config.OAuthConfig{})
	request.Open = nil
	request.Announce = func(string) { cancel() }
	err := Login(ctx, request)
	if err == nil || strings.Contains(err.Error(), "no authorization within") {
		t.Fatalf("a canceled login is not a timeout, got %v", err)
	}
}

func TestLoginAnnouncesTheAuthorizationURL(t *testing.T) {
	fake := newFakeServer(t)
	var announced string
	request := loginRequest(fake, store.NewMemory(), config.OAuthConfig{})
	request.Announce = func(authURL string) { announced = authURL }
	if err := Login(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(announced, fake.server.URL+"/authorize?") {
		t.Fatalf("announced %q", announced)
	}
}

// failingWrites fails the writes and deletes of one account.
type failingWrites struct {
	store.Store
	failOn string
}

func (f failingWrites) Set(account, secret string) error {
	if account == f.failOn {
		return errors.New("write denied")
	}
	return f.Store.Set(account, secret)
}

func (f failingWrites) Delete(account string) (bool, error) {
	if account == f.failOn {
		return false, errors.New("delete denied")
	}
	return f.Store.Delete(account)
}

func TestLoginTellsToRetryWhenOnlyTheClientRecordFailsToSave(t *testing.T) {
	fake := newFakeServer(t)
	memory := store.NewMemory()
	request := loginRequest(fake, failingWrites{Store: memory, failOn: "oauth-client.sentry"}, config.OAuthConfig{})
	err := Login(context.Background(), request)
	want := "the tokens were saved, but the OAuth client record could not be written: run `toolward auth login sentry` again"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v", err)
	}
}

func TestLoginReportsATokenSaveFailure(t *testing.T) {
	fake := newFakeServer(t)
	request := loginRequest(fake, failingWrites{Store: store.NewMemory(), failOn: "oauth.sentry"}, config.OAuthConfig{})
	if err := Login(context.Background(), request); err == nil {
		t.Fatal("expected an error")
	}
}
