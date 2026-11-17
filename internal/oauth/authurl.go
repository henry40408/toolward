package oauth

import (
	"errors"
	"net/url"
	"strings"
)

// ValidatedAuthURL parses the URL the user is sent to. Only https is
// accepted, or http on loopback.
func ValidatedAuthURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return nil, errors.New("the server gave an invalid authorization URL")
	}
	if parsed.Scheme == "https" || parsed.Scheme == "http" && isLoopbackAuthHost(parsed.Hostname()) {
		return parsed, nil
	}
	return nil, errors.New("the server's authorization URL is not https")
}

func isLoopbackAuthHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// AuthURLState returns the state of an authorization URL. Only the browser
// that was sent there knows it, so the callback is checked against it.
func AuthURLState(authURL *url.URL) (string, error) {
	if !authURL.Query().Has("state") {
		return "", errors.New("the authorization URL has no state")
	}
	return authURL.Query().Get("state"), nil
}
