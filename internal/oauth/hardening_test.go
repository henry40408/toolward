package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/henry40408/toolward/internal/config"
	"github.com/henry40408/toolward/internal/store"
	"github.com/henry40408/toolward/internal/upstream"
)

func TestTheCallbackReadsAtMost8KBAndWaitsFiveSeconds(t *testing.T) {
	callback, results, cancel := startWait(t, "s1")
	defer cancel()
	// The state sits behind the 8 KB the callback reads, so it never sees it.
	long := get("/callback?code=ok&pad=" + strings.Repeat("a", 9000) + "&state=s1")
	if reply := request(t, callback, long); !strings.Contains(reply, " 400 ") {
		t.Fatalf("got %q", reply)
	}
	select {
	case result := <-results:
		t.Fatalf("the wait must continue: %+v", result)
	default:
	}
	fresh, err := ListenCallback(0)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if fresh.readTimeout != 5*time.Second {
		t.Fatalf("read timeout %v", fresh.readTimeout)
	}
}

func TestAnErrorRedirectWithTheWrongStateIsIgnored(t *testing.T) {
	callback, results, cancel := startWait(t, "s1")
	defer cancel()
	if reply := request(t, callback, get("/callback?error=access_denied&state=other")); !strings.Contains(reply, " 400 ") {
		t.Fatalf("got %q", reply)
	}
	select {
	case result := <-results:
		t.Fatalf("the wait must continue: %+v", result)
	default:
	}
}

func TestLoginKeepsTheFieldsOfAFormEncodedTokenResponse(t *testing.T) {
	fake := newFakeServer(t)
	fake.formTokens = true
	memory := store.NewMemory()
	if err := Login(context.Background(), loginRequest(fake, memory, config.OAuthConfig{})); err != nil {
		t.Fatal(err)
	}
	response := loadCredentials(t, memory).TokenResponse
	if response.AccessToken != "access-1" || response.ExpiresIn == nil || *response.ExpiresIn != 3600 {
		t.Fatalf("got %+v", response)
	}
	if _, found := response.Extra["extra"]; !found || response.RefreshToken == nil {
		t.Fatalf("got %+v", response)
	}
}

func TestLoginRefusesAnEndpointThatSetsItsOwnState(t *testing.T) {
	fake := newFakeServer(t)
	fake.authorizeSuffix = "?state=FIXED"
	err := Login(context.Background(), loginRequest(fake, store.NewMemory(), config.OAuthConfig{}))
	if err == nil || !strings.Contains(err.Error(), "sets its own state") {
		t.Fatalf("got %v", err)
	}
}

func TestRefreshErrorsNeverShowTheStoredTokens(t *testing.T) {
	fake := newFakeServer(t)
	memory := loggedIn(t, fake)
	expire(t, memory)
	fake.refreshGrant = "echo"
	_, err := connectorFor(fake, memory).Connect(context.Background(), &upstream.Handler{})
	if err == nil || strings.Contains(err.Error(), "refresh-1") || !strings.Contains(err.Error(), "refresh failed") {
		t.Fatalf("got %v", err)
	}
}

func proxyRecorder(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

// proxiedClients are the clients of a public server in an environment that has
// a proxy.
func proxiedClients(t *testing.T, proxy *httptest.Server) *HTTPClients {
	t.Helper()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	return NewHTTPClients(mustParse(t, "https://mcp.example.com/mcp"))
}

func getWith(client *http.Client, target string) error {
	answer, err := client.Get(target)
	if err == nil {
		_ = answer.Body.Close()
	}
	return err
}

func TestTheProxyIsReachedEvenThoughItIsOnLoopback(t *testing.T) {
	proxy, hits := proxyRecorder(t)
	clients := proxiedClients(t, proxy)
	if err := getWith(clients.Stop, "http://as.example.com/token"); err != nil || hits.Load() != 1 {
		t.Fatalf("err %v, hits %d", err, hits.Load())
	}
}

func TestAnIPLiteralEndpointIsRefusedWithAProxy(t *testing.T) {
	proxy, hits := proxyRecorder(t)
	clients := proxiedClients(t, proxy)
	err := getWith(clients.Stop, "http://169.254.169.254/latest/meta-data")
	if err == nil || !strings.Contains(err.Error(), "not allowed") || hits.Load() != 0 {
		t.Fatalf("err %v, hits %d", err, hits.Load())
	}
}

func TestANonCanonicalNumericHostIsRefusedWithAProxy(t *testing.T) {
	proxy, hits := proxyRecorder(t)
	clients := proxiedClients(t, proxy)
	for _, host := range []string{"2130706433", "0x7f000001", "127.1", "127.0.0.1.", "0177.0.0.1"} {
		err := getWith(clients.Stop, "http://"+host+"/")
		if err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("%s: got %v", host, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("the proxy was reached %d times", hits.Load())
	}
}

func TestADirectTargetIsCheckedEvenWithAProxyConfigured(t *testing.T) {
	proxy, hits := proxyRecorder(t)
	clients := proxiedClients(t, proxy)
	// The environment never proxies localhost, so this dial is the client's own.
	target := httptest.NewServer(http.NotFoundHandler())
	defer target.Close()
	port := target.URL[strings.LastIndex(target.URL, ":"):]
	err := getWith(clients.Stop, "http://localhost"+port+"/")
	if err == nil || !strings.Contains(err.Error(), "not allowed") || hits.Load() != 0 {
		t.Fatalf("err %v, hits %d", err, hits.Load())
	}
}

func TestARedirectToAnIPLiteralIsRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	clients := NewHTTPClients(mustParse(t, server.URL))
	err := getWith(clients.Follow, server.URL+"/register")
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("got %v", err)
	}
}
