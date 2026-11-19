package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// AuthorizationMetadata is the document of RFC 8414 or OpenID Connect
// discovery, reduced to what toolward uses.
type AuthorizationMetadata struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	RegistrationEndpoint  *string
	Issuer                *string
	ScopesSupported       []string
	// ResponseTypesSupported is nil when the server did not say.
	ResponseTypesSupported *[]string
	// CodeChallengeMethods is nil when the server did not say.
	CodeChallengeMethods *[]string
	// TokenAuthMethods is token_endpoint_auth_methods_supported.
	TokenAuthMethods []string
	// IssuerInResponse is authorization_response_iss_parameter_supported.
	IssuerInResponse bool
}

type metadataWire struct {
	AuthorizationEndpoint  *string   `json:"authorization_endpoint"`
	TokenEndpoint          *string   `json:"token_endpoint"`
	RegistrationEndpoint   *string   `json:"registration_endpoint"`
	Issuer                 *string   `json:"issuer"`
	ScopesSupported        []string  `json:"scopes_supported"`
	ResponseTypesSupported *[]string `json:"response_types_supported"`
	CodeChallengeMethods   *[]string `json:"code_challenge_methods_supported"`
	TokenAuthMethods       []string  `json:"token_endpoint_auth_methods_supported"`
	IssuerInResponse       *bool     `json:"authorization_response_iss_parameter_supported"`
}

// parseAuthorizationMetadata is false for a body that is not a metadata
// document with both endpoints.
func parseAuthorizationMetadata(body []byte) (AuthorizationMetadata, bool) {
	var wire *metadataWire
	if json.Unmarshal(body, &wire) != nil || wire == nil || wire.AuthorizationEndpoint == nil || wire.TokenEndpoint == nil {
		return AuthorizationMetadata{}, false
	}
	return AuthorizationMetadata{
		AuthorizationEndpoint:  *wire.AuthorizationEndpoint,
		TokenEndpoint:          *wire.TokenEndpoint,
		RegistrationEndpoint:   wire.RegistrationEndpoint,
		Issuer:                 wire.Issuer,
		ScopesSupported:        wire.ScopesSupported,
		ResponseTypesSupported: wire.ResponseTypesSupported,
		CodeChallengeMethods:   wire.CodeChallengeMethods,
		TokenAuthMethods:       wire.TokenAuthMethods,
		IssuerInResponse:       wire.IssuerInResponse != nil && *wire.IssuerInResponse,
	}, true
}

// legacyMetadata is the endpoints that servers of the 2025-03-26 revision
// had by default. They are used only when discovery found nothing.
func legacyMetadata(base *url.URL) AuthorizationMetadata {
	endpoint := func(path string) string { return withPath(base, path).String() }
	registration := endpoint("/register")
	return AuthorizationMetadata{
		AuthorizationEndpoint: endpoint("/authorize"),
		TokenEndpoint:         endpoint("/token"),
		RegistrationEndpoint:  &registration,
	}
}

// ValidateForCodeFlow refuses a server that cannot do the flow toolward runs:
// the authorization code with an S256 challenge.
func (m AuthorizationMetadata) ValidateForCodeFlow() error {
	if m.ResponseTypesSupported != nil && !contains(*m.ResponseTypesSupported, "code") {
		return errors.New("Invalid scope: code") //nolint:staticcheck // ST1005: user-facing text that matches rmcp
	}
	if m.CodeChallengeMethods != nil && !contains(*m.CodeChallengeMethods, "S256") {
		return errors.New("Authorization server does not support the required PKCE code challenge method (S256)")
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// withPath returns the URL with another path and without query and fragment.
func withPath(base *url.URL, path string) *url.URL {
	copied := *base
	copied.Path = path
	copied.RawPath = ""
	copied.RawQuery = ""
	copied.Fragment = ""
	copied.RawFragment = ""
	return &copied
}

// wellKnownPaths lists where RFC 9728 and common practice put a document.
func wellKnownPaths(basePath, resource string) []string {
	trimmed := strings.Trim(basePath, "/")
	canonical := "/.well-known/" + resource
	if trimmed == "" {
		return []string{canonical}
	}
	return []string{canonical + "/" + trimmed, "/" + trimmed + "/.well-known/" + resource, canonical}
}

// discoveryPaths lists where an authorization server publishes its metadata.
func discoveryPaths(basePath string) []string {
	trimmed := strings.Trim(basePath, "/")
	const oauthPath = "/.well-known/oauth-authorization-server"
	const oidcPath = "/.well-known/openid-configuration"
	if trimmed == "" {
		return []string{oauthPath, oidcPath}
	}
	return []string{oauthPath + "/" + trimmed, oidcPath + "/" + trimmed, "/" + trimmed + oidcPath, oauthPath}
}

// expectedIssuer is the issuer a metadata document must name, derived from the
// URL it was served from. It is "" for an address that is not a metadata
// location.
func expectedIssuer(discoveryURL *url.URL) string {
	const oauthPath = "/.well-known/oauth-authorization-server"
	const oidcPath = "/.well-known/openid-configuration"
	path := discoveryURL.Path
	var issuerPath string
	switch {
	case path == oauthPath || path == oidcPath:
	case strings.HasPrefix(path, oauthPath+"/"):
		issuerPath = strings.TrimPrefix(path, oauthPath+"/")
	case strings.HasPrefix(path, oidcPath+"/"):
		issuerPath = strings.TrimPrefix(path, oidcPath+"/")
	case strings.HasSuffix(path, oidcPath):
		issuerPath = strings.TrimLeft(strings.TrimSuffix(path, oidcPath), "/")
	default:
		return ""
	}
	return withPath(discoveryURL, "/"+issuerPath).String()
}

// sameIssuer compares two issuer identifiers, ignoring the slash of a root.
func sameIssuer(received, expected string) bool {
	return received == expected || trimRootSlash(received) == trimRootSlash(expected)
}

func trimRootSlash(issuer string) string {
	without, found := strings.CutSuffix(issuer, "/")
	if !found {
		return issuer
	}
	parsed, err := url.Parse(without)
	if err != nil || (parsed.Path != "" && parsed.Path != "/") {
		return issuer
	}
	return without
}

// ResourceMetadata is the protected resource metadata of RFC 9728.
type resourceMetadata struct {
	Resource             *string  `json:"resource"`
	AuthorizationServer  *string  `json:"authorization_server"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

func (m *resourceMetadata) namesAuthorizationServer() bool {
	return m.AuthorizationServer != nil || m.AuthorizationServers != nil
}

// validateResource checks that the document is about the server at base.
func (m *resourceMetadata) validateResource(base *url.URL) error {
	if m.Resource == nil {
		return errors.New("Protected resource metadata missing required resource field") //nolint:staticcheck // ST1005: user-facing text that matches rmcp
	}
	resource, err := url.Parse(*m.Resource)
	if err != nil || resource.Scheme == "" {
		return fmt.Errorf("Protected resource metadata resource field is not a valid URL: %s", *m.Resource) //nolint:staticcheck // ST1005: user-facing text that matches rmcp
	}
	if resource.Fragment != "" || strings.Contains(*m.Resource, "#") {
		return errors.New("Protected resource metadata resource does not permit fragment in URL as specified by RFC 8707") //nolint:staticcheck // ST1005: user-facing text that matches rmcp
	}
	if !isResourceIdentifierValid(base, resource) {
		return fmt.Errorf("Protected resource metadata resource mismatch: reference '%s', permitted '%s'", base, resource) //nolint:staticcheck // ST1005: user-facing text that matches rmcp
	}
	return nil
}

// isResourceIdentifierValid accepts a resource that is the server's URL or a
// parent path of it.
func isResourceIdentifierValid(expected, actual *url.URL) bool {
	if expected.String() == actual.String() {
		return true
	}
	if expected.Scheme != actual.Scheme || !strings.EqualFold(expected.Hostname(), actual.Hostname()) || portOf(expected) != portOf(actual) {
		return false
	}
	if expected.Path == actual.Path {
		return true
	}
	if !strings.HasPrefix(expected.Path, actual.Path) {
		return false
	}
	return strings.HasSuffix(actual.Path, "/") || expected.Path[len(actual.Path)] == '/'
}
