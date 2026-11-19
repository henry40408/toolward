package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Discovery is what is known about the authorization of a server.
type Discovery struct {
	Metadata AuthorizationMetadata
	Hints    ScopeHints
	// Resource is the resource indicator of RFC 8707 to send with requests.
	Resource string
}

// Discover finds the authorization server of the MCP server at base the way
// rmcp 3.9.0 does: protected resource metadata (RFC 9728) first, then the
// metadata of the server itself (RFC 8414, then OpenID Connect), then the
// default endpoints of the 2025-03-26 revision.
func Discover(ctx context.Context, base *url.URL, client *http.Client) (*Discovery, error) {
	finder := &finder{base: base, client: client}
	metadata, err := finder.resolve(ctx)
	if err != nil {
		return nil, err
	}
	resource := finder.resource
	if resource == "" {
		resource = base.String()
	}
	return &Discovery{Metadata: metadata, Hints: finder.hints, Resource: resource}, nil
}

type finder struct {
	base   *url.URL
	client *http.Client
	hints  ScopeHints
	// resource is the "resource" of the protected resource metadata.
	resource string
}

// origin says where a metadata URL came from, which decides what a document
// that is not metadata means.
type origin int

const (
	originAdvertised origin = iota
	originGuessed
)

func (f *finder) resolve(ctx context.Context) (AuthorizationMetadata, error) {
	metadata, err := f.viaResourceMetadata(ctx)
	if err != nil || metadata != nil {
		return derefMetadata(metadata), err
	}
	metadata, err = f.tryAuthorizationServer(ctx, f.base, "")
	if err != nil || metadata != nil {
		return derefMetadata(metadata), err
	}
	return legacyMetadata(f.base), nil
}

func derefMetadata(metadata *AuthorizationMetadata) AuthorizationMetadata {
	if metadata == nil {
		return AuthorizationMetadata{}
	}
	return *metadata
}

type foundResource struct {
	url      *url.URL
	metadata *resourceMetadata
}

func (f *finder) viaResourceMetadata(ctx context.Context) (*AuthorizationMetadata, error) {
	found, err := f.findResourceMetadata(ctx)
	if err != nil || found == nil {
		return nil, err
	}
	return f.fromResourceMetadata(ctx, found)
}

// findResourceMetadata looks for the document where the server points to it,
// then at the well-known locations.
func (f *finder) findResourceMetadata(ctx context.Context) (*foundResource, error) {
	requested := map[string]bool{}
	advertised, err := f.probeForPointer(ctx)
	if err != nil {
		return nil, err
	}
	if advertised != nil {
		requested[advertised.String()] = true
		metadata, err := f.fetchResourceMetadata(ctx, advertised, originAdvertised)
		if err != nil || metadata != nil {
			return foundOrNil(advertised, metadata), err
		}
	}
	for _, path := range wellKnownPaths(f.base.Path, "oauth-protected-resource") {
		candidate := withPath(f.base, path)
		if requested[candidate.String()] {
			continue
		}
		requested[candidate.String()] = true
		found, err := f.tryWellKnown(ctx, candidate, requested)
		if err != nil || found != nil {
			return found, err
		}
	}
	return nil, nil
}

func foundOrNil(location *url.URL, metadata *resourceMetadata) *foundResource {
	if metadata == nil {
		return nil
	}
	return &foundResource{url: location, metadata: metadata}
}

// tryWellKnown asks one guessed location. A 401 there may point to the real
// document.
func (f *finder) tryWellKnown(ctx context.Context, candidate *url.URL, requested map[string]bool) (*foundResource, error) {
	answer, err := discoveryGet(ctx, f.client, candidate)
	if err != nil {
		return nil, discoveryFailed(candidate, err)
	}
	switch answer.Status {
	case http.StatusOK:
		metadata, err := f.readResourceMetadata(candidate, answer.Body, originGuessed)
		return foundOrNil(candidate, metadata), err
	case http.StatusUnauthorized:
		pointer := f.pointerOf(answer.Header)
		if pointer == nil || requested[pointer.String()] {
			return nil, nil
		}
		requested[pointer.String()] = true
		metadata, err := f.fetchResourceMetadata(ctx, pointer, originGuessed)
		return foundOrNil(pointer, metadata), err
	}
	return nil, nil
}

// probeForPointer asks the server itself, looking only for a challenge that
// points to the resource metadata. A 200 says nothing about metadata.
func (f *finder) probeForPointer(ctx context.Context) (*url.URL, error) {
	answer, err := discoveryGet(ctx, f.client, f.base)
	if err != nil {
		return nil, discoveryFailed(f.base, err)
	}
	if answer.Status != http.StatusUnauthorized {
		return nil, nil
	}
	return f.pointerOf(answer.Header), nil
}

// pointerOf returns the resource metadata URL of a 401 and remembers the scope
// of the challenge that carried it.
func (f *finder) pointerOf(headers http.Header) *url.URL {
	challenge := pickChallenge(headers, f.base)
	if challenge == nil || challenge.ResourceMetadataURL == nil {
		return nil
	}
	if challenge.Scope != nil {
		if scopes := strings.Fields(*challenge.Scope); len(scopes) > 0 {
			f.hints.Challenge = scopes
		}
	}
	return challenge.ResourceMetadataURL
}

func (f *finder) fetchResourceMetadata(ctx context.Context, location *url.URL, from origin) (*resourceMetadata, error) {
	answer, err := discoveryGet(ctx, f.client, location)
	if err != nil {
		return nil, discoveryFailed(location, err)
	}
	if answer.Status != http.StatusOK {
		return nil, nil
	}
	return f.readResourceMetadata(location, answer.Body, from)
}

// readResourceMetadata reads a body as the metadata of this server. A body
// that is not that rules out its URL. Where the URL came from decides whether
// that is an error: a server that named the URL has nothing better to offer,
// a guess only fails.
func (f *finder) readResourceMetadata(location *url.URL, body []byte, from origin) (*resourceMetadata, error) {
	var metadata *resourceMetadata
	if json.Unmarshal(body, &metadata) != nil || metadata == nil {
		return nil, nil
	}
	if metadata.Resource == nil && !metadata.namesAuthorizationServer() {
		return nil, invalidResourceMetadata(location, from, "the document carries neither `resource` nor an authorization server reference")
	}
	if err := metadata.validateResource(f.base); err != nil {
		return nil, invalidResourceMetadata(location, from, err.Error())
	}
	return metadata, nil
}

func invalidResourceMetadata(location *url.URL, from origin, reason string) error {
	if from == originGuessed {
		return nil
	}
	return fmt.Errorf("Protected resource metadata at %s is unusable: %s", redactedURL(location), reason) //nolint:staticcheck // ST1005: user-facing text that matches rmcp
}

// fromResourceMetadata walks the authorization servers the document names and
// keeps the first that answers. A document that names servers none of which
// answers is an error: going elsewhere would send the user to a place the
// resource never named.
func (f *finder) fromResourceMetadata(ctx context.Context, found *foundResource) (*AuthorizationMetadata, error) {
	document := found.metadata
	if document.Resource != nil {
		f.resource = *document.Resource
	}
	if len(document.ScopesSupported) > 0 {
		f.hints.Resource = document.ScopesSupported
	}
	candidates := serverCandidates(document)
	for _, candidate := range candidates {
		metadata, err := f.tryCandidate(ctx, found.url, candidate)
		if err != nil || metadata != nil {
			return metadata, err
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	return nil, fmt.Errorf("Protected resource metadata at %s names authorization servers %s, but none published usable metadata", //nolint:staticcheck // ST1005: user-facing text that matches rmcp
		redactedURL(found.url), strings.Join(candidates, ", "))
}

// serverCandidates lists the named servers once each. A document may give the
// same server in the draft's singular field and in the list.
func serverCandidates(document *resourceMetadata) []string {
	var candidates []string
	add := func(candidate string) {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" && !contains(candidates, candidate) {
			candidates = append(candidates, candidate)
		}
	}
	if document.AuthorizationServer != nil {
		add(*document.AuthorizationServer)
	}
	for _, candidate := range document.AuthorizationServers {
		add(candidate)
	}
	return candidates
}

func (f *finder) tryCandidate(ctx context.Context, documentURL *url.URL, candidate string) (*AuthorizationMetadata, error) {
	location, err := documentURL.Parse(candidate)
	if err != nil || !isAllowedMetadataURL(f.base, location) {
		return nil, nil
	}
	if strings.Contains(location.Path, "/.well-known/") {
		return f.fetchAuthorizationMetadata(ctx, location, "")
	}
	// The issuer the document advertised is compared as written.
	return f.tryAuthorizationServer(ctx, location, location.String())
}

func (f *finder) tryAuthorizationServer(ctx context.Context, server *url.URL, issuer string) (*AuthorizationMetadata, error) {
	for _, path := range discoveryPaths(server.Path) {
		metadata, err := f.fetchAuthorizationMetadata(ctx, withPath(server, path), issuer)
		if err != nil || metadata != nil {
			return metadata, err
		}
	}
	return nil, nil
}

func (f *finder) fetchAuthorizationMetadata(ctx context.Context, location *url.URL, issuer string) (*AuthorizationMetadata, error) {
	answer, err := discoveryGet(ctx, f.client, location)
	if err != nil {
		return nil, discoveryFailed(location, err)
	}
	if answer.Status != http.StatusOK {
		return nil, nil
	}
	metadata, ok := parseAuthorizationMetadata(answer.Body)
	if !ok {
		return nil, nil
	}
	if err := checkIssuer(location, issuer, metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

// checkIssuer binds a metadata document to the place it was fetched from.
func checkIssuer(location *url.URL, issuer string, metadata AuthorizationMetadata) error {
	if issuer == "" {
		issuer = expectedIssuer(location)
	}
	if issuer == "" {
		return nil
	}
	if metadata.Issuer == nil {
		return fmt.Errorf("Authorization server response missing required issuer: expected %s", issuer)
	}
	if !sameIssuer(*metadata.Issuer, issuer) {
		return fmt.Errorf("Authorization server issuer mismatch: expected %s, received %s", issuer, *metadata.Issuer)
	}
	return nil
}

func discoveryFailed(location *url.URL, err error) error {
	return fmt.Errorf("OAuth metadata discovery failed for %s: %w", redactedURL(location), err)
}

// redactedURL is the URL without user info, query and fragment. They may hold
// credentials, and error text reaches logs.
func redactedURL(location *url.URL) string {
	copied := *location
	copied.User = nil
	copied.RawQuery = ""
	copied.Fragment = ""
	copied.RawFragment = ""
	return copied.String()
}
