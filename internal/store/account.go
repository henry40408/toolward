package store

import (
	"errors"
	"fmt"
	"strings"
)

// Service is the Keychain service under which every toolward secret is stored.
const Service = "toolward"

// ReservedPrefixes are the account prefixes that only `toolward auth login`
// may write: the tokens ("oauth.") and a dynamically registered client secret
// ("oauth-client.").
var ReservedPrefixes = []string{"oauth.", "oauth-client."}

// ErrUnsupported means the platform has no credential store.
var ErrUnsupported = errors.New("no credential store is available on this platform")

// InvalidAccountError reports an account name with characters outside the allowed set.
type InvalidAccountError struct{ Account string }

func (e *InvalidAccountError) Error() string {
	return fmt.Sprintf("invalid account name %q: use only ASCII letters, digits, '.', '_' and '-'", e.Account)
}

// ReservedAccountError reports a user account name that uses a reserved prefix.
type ReservedAccountError struct{ Account string }

func (e *ReservedAccountError) Error() string {
	return fmt.Sprintf("account names starting with \"oauth.\" or \"oauth-client.\" are reserved for OAuth logins: %q", e.Account)
}

// BackendError wraps a failure of the underlying credential store.
type BackendError struct{ Message string }

func (e *BackendError) Error() string {
	return "credential store failure: " + e.Message
}

// ValidateAccount checks an account name. The same charset is accepted inside
// "${keychain:...}".
func ValidateAccount(account string) error {
	if account == "" || strings.IndexFunc(account, isForbiddenAccountRune) >= 0 {
		return &InvalidAccountError{Account: account}
	}
	return nil
}

func isForbiddenAccountRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return false
	case r == '.', r == '_', r == '-':
		return false
	}
	return true
}

// ValidateUserAccount is like ValidateAccount, for names a user picks: the
// reserved prefixes are for what `toolward auth login` stores.
func ValidateUserAccount(account string) error {
	if err := ValidateAccount(account); err != nil {
		return err
	}
	for _, prefix := range ReservedPrefixes {
		if strings.HasPrefix(account, prefix) {
			return &ReservedAccountError{Account: account}
		}
	}
	return nil
}
