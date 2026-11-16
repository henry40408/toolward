// Package store holds credential storage backends.
//
// Secrets are addressed by an account name. Config files only ever hold
// references to accounts, never the secret values.
package store

// Store is a credential store. Implementations are safe for concurrent use.
type Store interface {
	// Get reports false when the account has no secret.
	Get(account string) (secret string, found bool, err error)
	Set(account, secret string) error
	// Delete reports true when a secret existed and was removed.
	Delete(account string) (bool, error)
}
