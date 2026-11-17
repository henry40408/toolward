package oauth

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestChallengeValueSyntax(t *testing.T) {
	base := mustParse(t, "https://mcp.example.com/api")
	tests := []struct {
		name         string
		header       string
		wantMetadata string
		wantScope    *string
	}{
		{"quoted with escapes", `Bearer resource_metadata="https://mcp.example.com/m\"x"`, `https://mcp.example.com/m%22x`, nil},
		{"unterminated quote", `Bearer resource_metadata="https://mcp.example.com/m`, "", nil},
		{"token ends at a comma", `Bearer resource_metadata=/m, scope=read`, "https://mcp.example.com/m", ptr("read")},
		{"token ends at a semicolon", `Bearer resource_metadata=/m;x`, "https://mcp.example.com/m", nil},
		{"token ends at a tab", "Bearer resource_metadata=/m\tx", "https://mcp.example.com/m", nil},
		{"token ends at the header end", `Bearer resource_metadata=/m`, "https://mcp.example.com/m", nil},
		{"upper case names", `Bearer RESOURCE_METADATA="/m" SCOPE="a b"`, "https://mcp.example.com/m", ptr("a b")},
		{"empty value is skipped for the next one", `Bearer resource_metadata="" resource_metadata=/second`, "https://mcp.example.com/second", nil},
		{"an https resource never goes down to http", `Bearer resource_metadata="http://other.example.com/m"`, "", nil},
		{"an internal host is refused", `Bearer resource_metadata="https://169.254.169.254/m"`, "", nil},
		{"a foreign https host is accepted", `Bearer resource_metadata="https://auth.example.org/m"`, "https://auth.example.org/m", nil},
		{"a bad URL is skipped", `Bearer resource_metadata="http://[::1"`, "", nil},
		{"a scope with an unterminated quote", `Bearer scope="a b`, "", nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ParseChallenge(test.header, base)
			gotMetadata := ""
			if got.ResourceMetadataURL != nil {
				gotMetadata = got.ResourceMetadataURL.String()
			}
			if gotMetadata != test.wantMetadata {
				t.Fatalf("metadata %q, want %q", gotMetadata, test.wantMetadata)
			}
			if (got.Scope == nil) != (test.wantScope == nil) || (got.Scope != nil && *got.Scope != *test.wantScope) {
				t.Fatalf("scope %v, want %v", got.Scope, test.wantScope)
			}
		})
	}
}

func TestPickChallengePrefersMetadataOverAScopeOnlyHeader(t *testing.T) {
	base := mustParse(t, "https://mcp.example.com/")
	headers := http.Header{}
	headers.Add("WWW-Authenticate", `Bearer scope="first"`)
	headers.Add("WWW-Authenticate", `Bearer scope="second"`)
	headers.Add("WWW-Authenticate", `Bearer resource_metadata="/meta"`)
	got := pickChallenge(headers, base)
	if got == nil || got.ResourceMetadataURL == nil || got.ResourceMetadataURL.Path != "/meta" {
		t.Fatalf("got %+v", got)
	}

	headers.Del("WWW-Authenticate")
	headers.Add("WWW-Authenticate", `Bearer realm="x"`)
	headers.Add("WWW-Authenticate", `Bearer scope="first"`)
	headers.Add("WWW-Authenticate", `Bearer scope="second"`)
	got = pickChallenge(headers, base)
	if got == nil || got.Scope == nil || *got.Scope != "first" {
		t.Fatalf("the first scope must win, got %+v", got)
	}

	headers.Set("WWW-Authenticate", `Bearer realm="x"`)
	if got := pickChallenge(headers, base); got != nil {
		t.Fatalf("got %+v", got)
	}
}

func TestHostPolicyClassifiesAddresses(t *testing.T) {
	tests := []struct {
		address    string
		disallowed bool
		class      addressClass
	}{
		{"8.8.8.8", false, classPublic},
		{"127.0.0.1", true, classLoopback},
		{"::1", true, classLoopback},
		{"10.1.2.3", true, classPrivate},
		{"100.64.0.1", true, classPrivate},
		{"fd00::1", true, classPrivate},
		{"169.254.169.254", true, classBlocked},
		{"0.0.0.0", true, classBlocked},
		{"255.255.255.255", true, classBlocked},
		{"198.18.0.1", true, classBlocked},
		{"224.0.0.1", true, classBlocked},
		{"fe80::1", true, classBlocked},
		{"ff02::1", true, classBlocked},
		{"::", true, classBlocked},
		{"2001::1", true, classBlocked},
		{"64:ff9b:1::1", true, classBlocked},
		{"2606:4700::1", false, classPublic},
		// Addresses that carry an IPv4 address take its class.
		{"::ffff:10.0.0.1", true, classPrivate},
		{"::ffff:8.8.8.8", false, classPublic},
		{"64:ff9b::7f00:1", true, classLoopback},
		{"::7f00:1", true, classLoopback},
		{"::a00:1", true, classPrivate},
		{"2002:a9fe:a9fe::1", true, classBlocked},
		{"2002:808:808::1", false, classPublic},
		{"fe80::1%eth0", true, classBlocked},
	}
	for _, test := range tests {
		ip := netip.MustParseAddr(test.address)
		if got := isDisallowedIP(ip); got != test.disallowed {
			t.Errorf("isDisallowedIP(%s) = %v", test.address, got)
		}
		if got := classOf(ip); got != test.class {
			t.Errorf("classOf(%s) = %v, want %v", test.address, got, test.class)
		}
	}
}

func TestEmbeddedIPv4IgnoresPlainAddresses(t *testing.T) {
	for _, address := range []string{"1.2.3.4", "::1", "::", "2606:4700::1"} {
		if got, ok := embeddedIPv4(netip.MustParseAddr(address)); ok {
			t.Errorf("embeddedIPv4(%s) = %v", address, got)
		}
	}
}

func TestMetadataURLPolicyForHostNames(t *testing.T) {
	remote := mustParse(t, "https://mcp.example.com/")
	loopback := mustParse(t, "http://localhost:8080/")
	tests := []struct {
		base      *url.URL
		candidate string
		want      bool
	}{
		{remote, "https://auth.example.org/m", true},
		{remote, "ftp://auth.example.org/m", false},
		{remote, "https://localhost/m", false},
		{remote, "https://app.localhost./m", false},
		{remote, "https://metadata.google.internal/m", false},
		{remote, "https://METADATA/m", false},
		{remote, "https://10.0.0.1/m", false},
		{remote, "https://[::ffff:10.0.0.1]/m", false},
		{loopback, "http://127.0.0.1:9/m", true},
		{loopback, "http://localhost:9/m", true},
		{loopback, "http://10.0.0.1/m", false},
		{loopback, "http://metadata/m", false},
	}
	for _, test := range tests {
		if got := isAllowedMetadataURL(test.base, mustParse(t, test.candidate)); got != test.want {
			t.Errorf("isAllowedMetadataURL(%s, %s) = %v", test.base, test.candidate, got)
		}
	}
}

func TestAddressPolicyAllowsOnlyTheClassOfTheResource(t *testing.T) {
	public := newAddressPolicy(mustParse(t, "https://mcp.example.com/"))
	loopbackName := newAddressPolicy(mustParse(t, "http://localhost/"))
	loopbackIP := newAddressPolicy(mustParse(t, "http://127.0.0.1/"))
	privateIP := newAddressPolicy(mustParse(t, "http://10.0.0.5/"))

	allowed := func(policy addressPolicy, address string) bool {
		return policy.allows(netip.MustParseAddr(address))
	}
	if !allowed(public, "8.8.8.8") || allowed(public, "127.0.0.1") || allowed(public, "10.0.0.1") {
		t.Error("a public resource may reach public addresses only")
	}
	if !allowed(loopbackName, "127.0.0.2") || allowed(loopbackName, "10.0.0.1") {
		t.Error("a loopback name may reach loopback only")
	}
	if !allowed(loopbackIP, "::1") || allowed(loopbackIP, "169.254.169.254") {
		t.Error("a loopback address may reach loopback, never link-local")
	}
	if !allowed(privateIP, "10.0.0.5") || !allowed(privateIP, "192.168.1.1") || allowed(privateIP, "127.0.0.1") {
		t.Error("a private address may reach private addresses, not loopback")
	}
	if allowed(public, "169.254.169.254") {
		t.Error("link-local must stay blocked")
	}
}

func TestAddressPolicyControlChecksTheDialedAddress(t *testing.T) {
	policy := newAddressPolicy(mustParse(t, "https://mcp.example.com/"))
	if err := policy.control("tcp", "8.8.8.8:443", nil); err != nil {
		t.Fatal(err)
	}
	err := policy.control("tcp", "127.0.0.1:443", nil)
	if err == nil || !strings.Contains(err.Error(), "address not allowed for OAuth requests") {
		t.Fatalf("got %v", err)
	}
	if err := policy.control("tcp", "no-port", nil); err == nil {
		t.Fatal("an address without a port must fail")
	}
	// A host name is not resolved here: the dialer passes literals.
	if err := policy.control("tcp", "example.com:443", nil); err == nil {
		t.Fatal("a name is not an address")
	}
}

func TestValidateForCodeFlowNamesWhatIsMissing(t *testing.T) {
	list := func(values ...string) *[]string { return &values }
	tests := []struct {
		name     string
		metadata AuthorizationMetadata
		want     string
	}{
		{"unknown support is fine", AuthorizationMetadata{}, ""},
		{"code and S256", AuthorizationMetadata{ResponseTypesSupported: list("token", "code"), CodeChallengeMethods: list("plain", "S256")}, ""},
		{"no code", AuthorizationMetadata{ResponseTypesSupported: list("token")}, "Invalid scope: code"},
		{"no S256", AuthorizationMetadata{CodeChallengeMethods: list("plain")}, "does not support the required PKCE code challenge method (S256)"},
	}
	for _, test := range tests {
		err := test.metadata.ValidateForCodeFlow()
		if test.want == "" && err != nil {
			t.Errorf("%s: %v", test.name, err)
		}
		if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Errorf("%s: got %v", test.name, err)
		}
	}
}

func TestParseAuthorizationMetadataRejectsDocumentsWithoutEndpoints(t *testing.T) {
	for _, body := range []string{``, `not json`, `null`, `[]`, `{}`, `{"authorization_endpoint":"https://a/x"}`} {
		if metadata, ok := parseAuthorizationMetadata([]byte(body)); ok {
			t.Errorf("%q parsed as %+v", body, metadata)
		}
	}
	metadata, ok := parseAuthorizationMetadata([]byte(`{"authorization_endpoint":"https://a/x","token_endpoint":"https://a/t"}`))
	if !ok || metadata.TokenEndpoint != "https://a/t" {
		t.Fatalf("got %+v, %v", metadata, ok)
	}
}

func TestExpectedIssuerFollowsTheMetadataLocation(t *testing.T) {
	tests := map[string]string{
		"https://a.example/.well-known/oauth-authorization-server":          "https://a.example/",
		"https://a.example/.well-known/openid-configuration":                "https://a.example/",
		"https://a.example/.well-known/oauth-authorization-server/tenant/1": "https://a.example/tenant/1",
		"https://a.example/.well-known/openid-configuration/tenant":         "https://a.example/tenant",
		"https://a.example/tenant/.well-known/openid-configuration":         "https://a.example/tenant",
		"https://a.example/somewhere/else":                                  "",
	}
	for location, want := range tests {
		if got := expectedIssuer(mustParse(t, location)); got != want {
			t.Errorf("expectedIssuer(%s) = %q, want %q", location, got, want)
		}
	}
}

func TestSameIssuerIgnoresTheSlashOfARootOnly(t *testing.T) {
	tests := []struct {
		received, expected string
		want               bool
	}{
		{"https://a.example", "https://a.example/", true},
		{"https://a.example/", "https://a.example", true},
		{"https://a.example/t", "https://a.example/t/", false},
		{"https://a.example/t", "https://a.example/t", true},
		{"https://a.example/", "https://b.example/", false},
		{"%zz/", "%zz", false},
	}
	for _, test := range tests {
		if got := sameIssuer(test.received, test.expected); got != test.want {
			t.Errorf("sameIssuer(%q, %q) = %v", test.received, test.expected, got)
		}
	}
}

func TestResourceMetadataValidation(t *testing.T) {
	base := mustParse(t, "https://mcp.example.com/api/v1")
	tests := []struct {
		name     string
		resource *string
		want     string
	}{
		{"missing", nil, "missing required resource field"},
		{"no scheme", ptr("mcp.example.com/api"), "is not a valid URL: mcp.example.com/api"},
		{"bad URL", ptr("http://[::1"), "is not a valid URL"},
		{"fragment", ptr("https://mcp.example.com/api#x"), "does not permit fragment"},
		{"empty fragment", ptr("https://mcp.example.com/api#"), "does not permit fragment"},
		{"other host", ptr("https://other.example.com/api"), "resource mismatch"},
		{"other scheme", ptr("http://mcp.example.com/api"), "resource mismatch"},
		{"other port", ptr("https://mcp.example.com:8443/api"), "resource mismatch"},
		{"not a path prefix", ptr("https://mcp.example.com/ap"), "resource mismatch"},
		{"exact", ptr("https://mcp.example.com/api/v1"), ""},
		{"parent path", ptr("https://mcp.example.com/api"), ""},
		{"parent with slash", ptr("https://mcp.example.com/api/"), ""},
		{"root", ptr("https://mcp.example.com/"), ""},
		{"case and default port", ptr("https://MCP.example.com:443/api"), ""},
	}
	for _, test := range tests {
		document := &resourceMetadata{Resource: test.resource}
		err := document.validateResource(base)
		if test.want == "" && err != nil {
			t.Errorf("%s: %v", test.name, err)
		}
		if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Errorf("%s: got %v", test.name, err)
		}
	}
}

func TestWellKnownAndDiscoveryPaths(t *testing.T) {
	if got := wellKnownPaths("/", "oauth-protected-resource"); len(got) != 1 || got[0] != "/.well-known/oauth-protected-resource" {
		t.Fatalf("got %v", got)
	}
	if got := wellKnownPaths("/a/b/", "x"); len(got) != 3 || got[0] != "/.well-known/x/a/b" || got[1] != "/a/b/.well-known/x" {
		t.Fatalf("got %v", got)
	}
	if got := discoveryPaths(""); len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if got := discoveryPaths("/t"); len(got) != 4 || got[2] != "/t/.well-known/openid-configuration" {
		t.Fatalf("got %v", got)
	}
}
