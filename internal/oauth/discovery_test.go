package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestDiscoveryFollowsTheResourceMetadata(t *testing.T) {
	fake := newFakeServer(t)
	base := mustParse(t, fake.mcpURL())
	discovery, err := Discover(context.Background(), base, NewHTTPClients(base).Stop)
	if err != nil {
		t.Fatal(err)
	}
	if discovery.Resource != fake.mcpURL() || *discovery.Metadata.Issuer != fake.server.URL {
		t.Fatalf("got %+v", discovery)
	}
	if len(discovery.Hints.Resource) != 1 || discovery.Hints.Resource[0] != "read" || len(discovery.Hints.Challenge) != 0 {
		t.Fatalf("hints %+v", discovery.Hints)
	}
}

func TestDiscoveryFallsBackToTheDefaultEndpoints(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	base := mustParse(t, server.URL+"/mcp")
	discovery, err := Discover(context.Background(), base, NewHTTPClients(base).Stop)
	if err != nil {
		t.Fatal(err)
	}
	if discovery.Metadata.AuthorizationEndpoint != server.URL+"/authorize" || discovery.Metadata.TokenEndpoint != server.URL+"/token" || discovery.Resource != base.String() {
		t.Fatalf("got %+v", discovery)
	}
}

func TestDiscoveryErrorsHideTheQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	base := mustParse(t, server.URL+"/mcp?key=TOPSECRET")
	_, err := Discover(context.Background(), base, NewHTTPClients(base).Stop)
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatalf("got %v", err)
	}
}

func TestMetadataURLPolicy(t *testing.T) {
	public := mustParse(t, "https://mcp.example.com/mcp")
	local := mustParse(t, "http://127.0.0.1:9000/mcp")
	cases := []struct {
		base      *url.URL
		candidate string
		allowed   bool
	}{
		{public, "https://auth.example.com", true},
		{public, "http://169.254.169.254/latest", false},
		{public, "http://10.0.0.5/x", false},
		{public, "http://localhost/x", false},
		{public, "http://[::1]/x", false},
		{public, "http://metadata.google.internal/x", false},
		{public, "ftp://auth.example.com", false},
		{local, "http://localhost:9001/x", true},
		{local, "http://10.0.0.5/x", false},
	}
	for _, c := range cases {
		if got := isAllowedMetadataURL(c.base, mustParse(t, c.candidate)); got != c.allowed {
			t.Errorf("%s from %s: got %v", c.candidate, c.base, got)
		}
	}
}

func TestChallengeParsing(t *testing.T) {
	base := mustParse(t, "https://mcp.example.com/mcp")
	challenge := ParseChallenge(`Bearer realm="x", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="read write"`, base)
	if challenge.ResourceMetadataURL == nil || challenge.ResourceMetadataURL.Path != "/.well-known/oauth-protected-resource/mcp" || challenge.Scope == nil || *challenge.Scope != "read write" {
		t.Fatalf("got %+v", challenge)
	}
	if ParseChallenge(`Basic realm="x"`, base).ResourceMetadataURL != nil {
		t.Fatal("a Basic challenge points nowhere")
	}
}

func TestIssuerValidationOfTheCallback(t *testing.T) {
	issuer, other := "https://as.example", "https://evil.example"
	required := AuthorizationMetadata{Issuer: &issuer, IssuerInResponse: true}
	cases := []struct {
		name     string
		metadata AuthorizationMetadata
		received *string
		want     string
	}{
		{"match", required, &issuer, ""},
		{"mismatch", required, &other, "Authorization server issuer mismatch: expected https://as.example, received https://evil.example"},
		{"missing but required", required, nil, "Authorization server response missing required issuer: expected https://as.example"},
		{"missing and optional", AuthorizationMetadata{Issuer: &issuer}, nil, ""},
		{"unrecorded", AuthorizationMetadata{}, &issuer, "OAuth authorization failed: Authorization callback issuer cannot be validated because expected issuer was not recorded"},
	}
	for _, c := range cases {
		err := validateIssuer(c.metadata, c.received)
		if (err == nil) != (c.want == "") || (err != nil && err.Error() != c.want) {
			t.Errorf("%s: got %v", c.name, err)
		}
	}
}

func TestRegistrationErrors(t *testing.T) {
	code, s256 := []string{"code"}, []string{"S256"}
	metadata := AuthorizationMetadata{ResponseTypesSupported: &code, CodeChallengeMethods: &s256}
	if _, err := Register(context.Background(), http.DefaultClient, metadata, RegistrationRequest{}); err == nil || err.Error() != "Registration failed: Dynamic client registration not supported" {
		t.Fatalf("got %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer server.Close()
	endpoint := server.URL
	metadata.RegistrationEndpoint = &endpoint
	_, err := Register(context.Background(), http.DefaultClient, metadata, RegistrationRequest{RedirectURI: "http://127.0.0.1:1/callback"})
	if err == nil || !strings.HasPrefix(err.Error(), "Registration failed: HTTP 403 Forbidden: nope") {
		t.Fatalf("got %v", err)
	}
}
