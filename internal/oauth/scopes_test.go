package oauth

import (
	"net/url"
	"slices"
	"testing"
)

func TestOfflineAccessIsAddedOnlyWhenTheServerSupportsIt(t *testing.T) {
	cases := []struct {
		name       string
		configured []string
		supported  []string
		want       []string
	}{
		{"supported", []string{"read"}, []string{"read", "offline_access"}, []string{"read", "offline_access"}},
		{"unsupported", []string{"read"}, []string{"read"}, []string{"read"}},
		{"unknown", []string{"read"}, nil, []string{"read"}},
		{"already asked", []string{"read", "offline_access"}, []string{"read", "offline_access"}, []string{"read", "offline_access"}},
	}
	for _, c := range cases {
		got := EffectiveScopes(c.configured, ScopeHints{Supported: c.supported})
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestConfiguredScopesAreNotChangedInPlace(t *testing.T) {
	configured := make([]string, 1, 4)
	configured[0] = "read"
	EffectiveScopes(configured, ScopeHints{Supported: []string{"offline_access"}})
	if configured[:2][1] != "" {
		t.Fatal("the caller's slice must not be written to")
	}
}

func TestServerSelectedScopesPreferWhatTheResourceAsks(t *testing.T) {
	cases := []struct {
		name  string
		hints ScopeHints
		want  []string
	}{
		{"challenge and resource", ScopeHints{Challenge: []string{"a", "b"}, Resource: []string{"b", "c"}, Supported: []string{"z"}}, []string{"a", "b", "c"}},
		{"resource only", ScopeHints{Resource: []string{"c"}, Supported: []string{"z"}}, []string{"c"}},
		{"authorization server", ScopeHints{Supported: []string{"x", "y"}}, []string{"x", "y"}},
		{"offline access", ScopeHints{Resource: []string{"c"}, Supported: []string{"offline_access"}}, []string{"c", "offline_access"}},
		{"nothing", ScopeHints{}, nil},
	}
	for _, c := range cases {
		if got := EffectiveScopes(nil, c.hints); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestTheAuthorizationURLMustBeHTTPSOrLoopbackHTTP(t *testing.T) {
	for _, raw := range []string{
		"https://auth.example.com/authorize",
		"http://localhost:8080/authorize",
		"http://127.0.0.1/authorize",
		"http://[::1]/authorize",
	} {
		if _, err := ValidatedAuthURL(raw); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
	rejected := map[string]string{
		"http://auth.example.com/authorize": "the server's authorization URL is not https",
		"ftp://localhost/authorize":         "the server's authorization URL is not https",
		"file:///etc/passwd":                "the server's authorization URL is not https",
		"not a url":                         "the server gave an invalid authorization URL",
	}
	for raw, want := range rejected {
		if _, err := ValidatedAuthURL(raw); err == nil || err.Error() != want {
			t.Errorf("%s: got %v, want %s", raw, err, want)
		}
	}
}

func TestTheAuthorizationURLMustCarryAState(t *testing.T) {
	withState, _ := url.Parse("https://a.example/authorize?state=s1&state=s2")
	if state, err := AuthURLState(withState); err != nil || state != "s1" {
		t.Fatalf("got %q, %v", state, err)
	}
	without, _ := url.Parse("https://a.example/authorize?x=1")
	if _, err := AuthURLState(without); err == nil || err.Error() != "the authorization URL has no state" {
		t.Fatalf("got %v", err)
	}
}
