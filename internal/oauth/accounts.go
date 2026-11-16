// Package oauth is OAuth 2.0 for HTTP upstreams.
//
// `toolward auth login <server>` runs the authorization-code flow once (PKCE,
// loopback redirect) and stores the tokens in the credential store. `toolward
// serve` only reads them, refreshes them when they expire, and never opens a
// browser.
package oauth

import (
	"fmt"

	"github.com/henry40408/toolward/internal/store"
)

// AccountFor is the credential-store account that holds a server's OAuth
// tokens.
func AccountFor(server string) (string, error) {
	account := "oauth." + server
	if store.ValidateAccount(account) != nil {
		return "", fmt.Errorf("server name %q cannot be used with oauth: use only ASCII letters, digits, '.', '_' and '-'", server)
	}
	return account, nil
}

// ClientAccountFor is the account that holds the client secret of a
// dynamically registered client. The token record has no room for it.
func ClientAccountFor(server string) (string, error) {
	if _, err := AccountFor(server); err != nil {
		return "", err
	}
	return "oauth-client." + server, nil
}

// IsLoggedIn says whether tokens are stored for a server, without reading
// their content.
func IsLoggedIn(secrets store.Store, server string) (bool, error) {
	account, err := AccountFor(server)
	if err != nil {
		return false, err
	}
	_, found, err := secrets.Get(account)
	return found, err
}

// Logout removes a server's login and its dynamic client record. It reports
// whether there was something. The record goes first, so a failure leaves the
// tokens (and a way to retry) in place.
func Logout(secrets store.Store, server string) (bool, error) {
	account, err := AccountFor(server)
	if err != nil {
		return false, err
	}
	clientAccount, err := ClientAccountFor(server)
	if err != nil {
		return false, err
	}
	hadClient, err := secrets.Delete(clientAccount)
	if err != nil {
		return false, err
	}
	hadTokens, err := secrets.Delete(account)
	if err != nil {
		return false, err
	}
	return hadTokens || hadClient, nil
}
