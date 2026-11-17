package config

import (
	"errors"
	"fmt"
)

// Transport is how to reach an upstream, after validation. Exactly one of
// Stdio and HTTP is set.
type Transport struct {
	Stdio *StdioTransport
	HTTP  *HTTPTransport
}

// StdioTransport runs a child process.
type StdioTransport struct {
	Command string
	Args    []string
	Env     map[string]string
}

// HTTPTransport talks to a streamable HTTP endpoint. OAuth is nil without OAuth.
type HTTPTransport struct {
	URL     string
	Headers map[string]string
	OAuth   *OAuthConfig
}

// Transport validates the transport fields of the server.
func (s *ServerConfig) Transport() (Transport, error) {
	if s.kindAllows("stdio") && s.Command != nil && s.URL == nil {
		return s.stdio()
	}
	if s.kindAllows("http") && s.Command == nil && s.URL != nil {
		return s.http()
	}
	return Transport{}, s.mismatch()
}

// kindAllows reports whether the "type" field is absent or names kind.
func (s *ServerConfig) kindAllows(kind string) bool {
	return s.Kind == nil || *s.Kind == kind
}

// mismatch explains why the fields do not form a transport.
func (s *ServerConfig) mismatch() error {
	switch {
	case s.Kind != nil && (*s.Kind == "stdio" || *s.Kind == "http"):
		return fmt.Errorf("type %q does not match the fields given", *s.Kind)
	case s.Kind != nil:
		return fmt.Errorf("unsupported type %q: expected \"stdio\" or \"http\"", *s.Kind)
	case s.Command != nil && s.URL != nil:
		return errors.New("set either 'command' or 'url', not both")
	}
	return errors.New("set either 'command' (stdio) or 'url' (http)")
}

func (s *ServerConfig) stdio() (Transport, error) {
	if len(s.Headers) > 0 || s.OAuth != nil {
		return Transport{}, errors.New("'headers' and 'oauth' apply only to http servers")
	}
	return Transport{Stdio: &StdioTransport{Command: *s.Command, Args: s.Args, Env: s.Env}}, nil
}

func (s *ServerConfig) http() (Transport, error) {
	if len(s.Args) > 0 || len(s.Env) > 0 {
		return Transport{}, errors.New("'args' and 'env' apply only to stdio servers")
	}
	if err := s.checkOAuth(); err != nil {
		return Transport{}, err
	}
	return Transport{HTTP: &HTTPTransport{URL: *s.URL, Headers: s.Headers, OAuth: s.OAuth}}, nil
}

func (s *ServerConfig) checkOAuth() error {
	if s.OAuth == nil {
		return nil
	}
	if len(s.Headers) > 0 {
		return errors.New("'headers' cannot be combined with 'oauth'")
	}
	if s.OAuth.ClientSecret != nil && s.OAuth.ClientID == nil {
		return errors.New("oauth 'clientSecret' needs 'clientId'")
	}
	return nil
}
