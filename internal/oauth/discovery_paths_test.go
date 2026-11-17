package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// routes answers by exact path; any other path is a 404.
type routes map[string]http.HandlerFunc

func serveRoutes(t *testing.T, table routes) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler, found := table[r.URL.Path]
		if !found {
			http.NotFound(w, r)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

func jsonRoute(body any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, body) }
}

func rawRoute(status int, header, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if header != "" {
			w.Header().Set("WWW-Authenticate", header)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func discoverAt(t *testing.T, server *httptest.Server, path string) (*Discovery, error) {
	t.Helper()
	base := mustParse(t, server.URL+path)
	return Discover(context.Background(), base, NewHTTPClients(base).Stop)
}

func authMetadata(server *httptest.Server, issuer string) map[string]any {
	return map[string]any{
		"issuer":                 issuer,
		"authorization_endpoint": server.URL + "/authorize",
		"token_endpoint":         server.URL + "/token",
	}
}

func TestDiscoveryFollowsTheChallengePointerAndKeepsItsScope(t *testing.T) {
	var server *httptest.Server
	server = serveRoutes(t, routes{
		"/mcp": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+server.URL+`/meta", scope="read write"`)
			w.WriteHeader(http.StatusUnauthorized)
		},
		"/meta": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{
				"resource":              server.URL + "/mcp",
				"authorization_servers": []string{server.URL, server.URL},
				"scopes_supported":      []string{"all"},
			})
		},
		"/.well-known/oauth-authorization-server": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, authMetadata(server, server.URL))
		},
	})
	discovery, err := discoverAt(t, server, "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(discovery.Hints.Challenge, ","); got != "read,write" {
		t.Fatalf("challenge scopes %q", got)
	}
	if got := strings.Join(discovery.Hints.Resource, ","); got != "all" {
		t.Fatalf("resource scopes %q", got)
	}
	if discovery.Resource != server.URL+"/mcp" {
		t.Fatalf("resource %q", discovery.Resource)
	}
}

func TestDiscoveryFollowsAPointerFromAGuessedLocation(t *testing.T) {
	var server *httptest.Server
	server = serveRoutes(t, routes{
		"/.well-known/oauth-protected-resource/mcp": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+server.URL+`/real"`)
			w.WriteHeader(http.StatusUnauthorized)
		},
		"/real": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, map[string]any{"resource": server.URL + "/mcp", "authorization_server": server.URL})
		},
		"/.well-known/oauth-authorization-server": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, authMetadata(server, server.URL))
		},
	})
	discovery, err := discoverAt(t, server, "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if discovery.Metadata.TokenEndpoint != server.URL+"/token" {
		t.Fatalf("got %+v", discovery.Metadata)
	}
}

func TestDiscoveryIgnoresAGuessedPointerThatLoopsBack(t *testing.T) {
	var server *httptest.Server
	server = serveRoutes(t, routes{
		"/.well-known/oauth-protected-resource/mcp": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+server.URL+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
		},
	})
	discovery, err := discoverAt(t, server, "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if discovery.Metadata.TokenEndpoint != server.URL+"/token" {
		t.Fatalf("the legacy endpoints are expected, got %+v", discovery.Metadata)
	}
}

func TestDiscoveryRejectsMetadataThatTheServerAdvertisedButCannotUse(t *testing.T) {
	tests := []struct {
		name     string
		document any
		want     string
	}{
		{"names nothing", map[string]any{"x": 1}, "carries neither `resource` nor an authorization server reference"},
		{"another resource", map[string]any{"resource": "https://elsewhere.example/mcp"}, "resource mismatch"},
		{"a fragment", map[string]any{"resource": "https://x.example/#f"}, "does not permit fragment"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var server *httptest.Server
			server = serveRoutes(t, routes{
				"/mcp": func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+server.URL+`/meta?key=TOPSECRET"`)
					w.WriteHeader(http.StatusUnauthorized)
				},
				"/meta": jsonRoute(test.document),
			})
			_, err := discoverAt(t, server, "/mcp")
			if err == nil || !strings.Contains(err.Error(), "is unusable: ") || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v", err)
			}
			if strings.Contains(err.Error(), "TOPSECRET") {
				t.Fatalf("the query leaked: %v", err)
			}
		})
	}
}

func TestDiscoverySkipsAGuessedDocumentThatIsNotMetadata(t *testing.T) {
	server := serveRoutes(t, routes{
		"/.well-known/oauth-protected-resource/mcp": rawRoute(200, "", "<html>not json</html>"),
		"/mcp/.well-known/oauth-protected-resource": jsonRoute(map[string]any{"resource": "https://elsewhere.example/"}),
		"/.well-known/oauth-protected-resource":     rawRoute(200, "", "null"),
	})
	discovery, err := discoverAt(t, server, "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if discovery.Resource != server.URL+"/mcp" {
		t.Fatalf("the resource must be the server URL, got %q", discovery.Resource)
	}
}

func TestDiscoveryFailsWhenNoNamedAuthorizationServerAnswers(t *testing.T) {
	var server *httptest.Server
	server = serveRoutes(t, routes{
		"/.well-known/oauth-protected-resource/mcp": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, map[string]any{
				"resource":              server.URL + "/mcp",
				"authorization_servers": []string{server.URL + "/gone", "http://169.254.169.254/", "http://[::1"},
			})
		},
	})
	_, err := discoverAt(t, server, "/mcp")
	if err == nil || !strings.Contains(err.Error(), "names authorization servers") || !strings.Contains(err.Error(), "none published usable metadata") {
		t.Fatalf("got %v", err)
	}
}

func TestDiscoveryAcceptsAMetadataURLAsAuthorizationServer(t *testing.T) {
	var server *httptest.Server
	server = serveRoutes(t, routes{
		"/.well-known/oauth-protected-resource/mcp": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, map[string]any{
				"resource":              server.URL + "/mcp",
				"authorization_servers": []string{server.URL + "/.well-known/oauth-authorization-server"},
			})
		},
		"/.well-known/oauth-authorization-server": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, authMetadata(server, server.URL))
		},
	})
	discovery, err := discoverAt(t, server, "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if *discovery.Metadata.Issuer != server.URL {
		t.Fatalf("got %+v", discovery.Metadata)
	}
}

func TestDiscoveryChecksTheIssuerAgainstTheLocation(t *testing.T) {
	var server *httptest.Server
	missing := map[string]any{"authorization_endpoint": "https://a/x", "token_endpoint": "https://a/t"}
	tests := []struct {
		name     string
		document func() any
		want     string
	}{
		{"missing", func() any { return missing }, "response missing required issuer: expected http"},
		{"mismatch", func() any { return authMetadata(server, "https://evil.example") }, "issuer mismatch: expected http"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server = serveRoutes(t, routes{
				"/.well-known/oauth-authorization-server": func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, test.document()) },
			})
			_, err := discoverAt(t, server, "/mcp")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestDiscoveryTriesTheOpenIDLocationAndSkipsABrokenDocument(t *testing.T) {
	var server *httptest.Server
	server = serveRoutes(t, routes{
		"/.well-known/oauth-authorization-server/mcp": rawRoute(200, "", "{not json"),
		"/.well-known/openid-configuration/mcp": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, authMetadata(server, server.URL+"/mcp"))
		},
	})
	discovery, err := discoverAt(t, server, "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if *discovery.Metadata.Issuer != server.URL+"/mcp" {
		t.Fatalf("got %+v", discovery.Metadata)
	}
}

func TestDiscoveryErrorsOnAnUnwellServer(t *testing.T) {
	for _, status := range []int{500, 429, 408, 425} {
		server := serveRoutes(t, routes{"/mcp": rawRoute(status, "", "")})
		_, err := discoverAt(t, server, "/mcp")
		if err == nil || !strings.Contains(err.Error(), "OAuth metadata discovery failed for ") || !strings.Contains(err.Error(), "unexpected HTTP status") {
			t.Fatalf("status %d: got %v", status, err)
		}
	}
}

func TestDiscoveryFollowsRedirectsWithinTheOriginOnly(t *testing.T) {
	var server *httptest.Server
	server = serveRoutes(t, routes{
		"/.well-known/oauth-authorization-server": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/moved", http.StatusFound)
		},
		"/moved": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, authMetadata(server, server.URL))
		},
	})
	// The redirect target is not a metadata path, so no issuer is enforced.
	if _, err := discoverAt(t, server, ""); err != nil {
		t.Fatal(err)
	}

	foreign := serveRoutes(t, routes{
		"/.well-known/oauth-authorization-server": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.example/x", http.StatusFound)
		},
	})
	_, err := discoverAt(t, foreign, "")
	if err == nil || !strings.Contains(err.Error(), "redirect to non-same-origin URL rejected") {
		t.Fatalf("got %v", err)
	}

	endless := serveRoutes(t, routes{
		"/.well-known/oauth-authorization-server": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, r.URL.Path, http.StatusFound)
		},
	})
	_, err = discoverAt(t, endless, "")
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("got %v", err)
	}
}

func TestDiscoveryTakesARedirectWithoutALocationAsTheAnswer(t *testing.T) {
	server := serveRoutes(t, routes{"/.well-known/oauth-authorization-server": rawRoute(302, "", "")})
	discovery, err := discoverAt(t, server, "")
	if err != nil {
		t.Fatal(err)
	}
	if discovery.Metadata.AuthorizationEndpoint != server.URL+"/authorize" {
		t.Fatalf("the legacy endpoints are expected, got %+v", discovery.Metadata)
	}
}

func TestDiscoveryReportsAnUnreachableServerWithoutItsQuery(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	address := server.URL
	server.Close()
	base := mustParse(t, address+"/mcp?key=TOPSECRET")
	_, err := Discover(context.Background(), base, NewHTTPClients(base).Stop)
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") || !strings.Contains(err.Error(), "OAuth metadata discovery failed for ") {
		t.Fatalf("got %v", err)
	}
}

func TestDiscoveryStopsOnACanceledContext(t *testing.T) {
	server := serveRoutes(t, routes{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	base := mustParse(t, server.URL+"/mcp")
	_, err := Discover(ctx, base, NewHTTPClients(base).Stop)
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("got %v", err)
	}
}

func TestDiscoveryRefusesAnOversizedAnswer(t *testing.T) {
	big := strings.Repeat("a", maxOAuthBodyBytes+10)
	server := serveRoutes(t, routes{"/mcp": rawRoute(200, "", big)})
	_, err := discoverAt(t, server, "/mcp")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("got %v", err)
	}
}
