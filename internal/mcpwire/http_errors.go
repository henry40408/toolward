package mcpwire

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrSessionExpired is the failure of a server that forgot the session: the
// connection cannot continue and must be opened again.
var ErrSessionExpired = errors.New("session expired (HTTP 404)")

// AuthorizationRequiredError means the server answered 401, or 403 for a
// token that lacks a scope, with a challenge.
type AuthorizationRequiredError struct {
	// Challenge is the WWW-Authenticate header.
	Challenge string
}

func (e *AuthorizationRequiredError) Error() string {
	return "authorization required: " + e.Challenge
}

// IsAuthorizationRequired says whether err asks for a login.
func IsAuthorizationRequired(err error) bool {
	var target *AuthorizationRequiredError
	return errors.As(err, &target)
}

// HTTPStatusError is a failed HTTP request that carried no JSON-RPC error.
type HTTPStatusError struct {
	Status int
	// Body is empty for 429 and 5xx, because a failing server may echo the
	// request headers into its page.
	Body string
}

func (e *HTTPStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("HTTP %d", e.Status)
	}
	return fmt.Sprintf("HTTP %d %s: %s", e.Status, http.StatusText(e.Status), e.Body)
}
