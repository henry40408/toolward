package config

import (
	"fmt"
	"maps"
	"slices"

	"github.com/henry40408/toolward/internal/interpolate"
)

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

// interpolatedStrings lists every string in which "${keychain:...}"
// references are expanded.
func (s *ServerConfig) interpolatedStrings() []string {
	var texts []string
	add := func(text *string) {
		if text != nil {
			texts = append(texts, *text)
		}
	}
	add(s.Command)
	add(s.URL)
	texts = append(texts, s.Args...)
	for _, key := range sortedKeys(s.Env) {
		texts = append(texts, s.Env[key])
	}
	for _, key := range sortedKeys(s.Headers) {
		texts = append(texts, s.Headers[key])
	}
	if s.OAuth != nil {
		add(s.OAuth.ClientID)
		add(s.OAuth.ClientSecret)
	}
	return texts
}

// References returns the accounts referenced by each server, sorted and
// without duplicates, without reading any secret.
func (c *Config) References() map[string][]string {
	references := make(map[string][]string, len(c.Servers))
	for name, server := range c.Servers {
		references[name] = server.accounts()
	}
	return references
}

func (s *ServerConfig) accounts() []string {
	var accounts []string
	for _, text := range s.interpolatedStrings() {
		found, _ := interpolate.References(text)
		accounts = append(accounts, found...)
	}
	slices.Sort(accounts)
	return slices.Compact(accounts)
}

// OAuthServers returns the names of the servers that use OAuth, sorted.
func (c *Config) OAuthServers() []string {
	var names []string
	for _, name := range c.Names() {
		server := c.Servers[name]
		if server.OAuth != nil && server.URL != nil {
			names = append(names, name)
		}
	}
	return names
}

// OAuthServer returns the URL and OAuth settings of a server, or why it has none.
func (c *Config) OAuthServer(name string) (url string, oauth *OAuthConfig, err error) {
	server, ok := c.Servers[name]
	if !ok {
		return "", nil, fmt.Errorf("no server named %q in the config", name)
	}
	transport, err := server.Transport()
	if err != nil {
		return "", nil, err
	}
	if transport.HTTP == nil || transport.HTTP.OAuth == nil {
		return "", nil, fmt.Errorf("server %q has no \"oauth\" setting", name)
	}
	return transport.HTTP.URL, transport.HTTP.OAuth, nil
}
