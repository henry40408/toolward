//go:build darwin

package store

import (
	"errors"

	"github.com/keybase/go-keychain"
)

// Keychain is the macOS login keychain. It talks to the Security framework
// directly: shelling out to /usr/bin/security would make every process able to
// read the secrets through it.
type Keychain struct{}

// NewKeychain returns the macOS Keychain store.
func NewKeychain() (Store, error) {
	return &Keychain{}, nil
}

func genericPassword(account string) keychain.Item {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(Service)
	item.SetAccount(account)
	return item
}

func (*Keychain) Get(account string) (string, bool, error) {
	if err := ValidateAccount(account); err != nil {
		return "", false, err
	}
	query := genericPassword(account)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)
	results, err := keychain.QueryItem(query)
	if err != nil {
		return "", false, &BackendError{Message: err.Error()}
	}
	if len(results) == 0 {
		return "", false, nil
	}
	return string(results[0].Data), true, nil
}

func (*Keychain) Set(account, secret string) error {
	if err := ValidateAccount(account); err != nil {
		return err
	}
	item := genericPassword(account)
	item.SetData([]byte(secret))
	err := keychain.AddItem(item)
	if errors.Is(err, keychain.ErrorDuplicateItem) {
		update := keychain.NewItem()
		update.SetData([]byte(secret))
		err = keychain.UpdateItem(genericPassword(account), update)
	}
	if err != nil {
		return &BackendError{Message: err.Error()}
	}
	return nil
}

func (*Keychain) Delete(account string) (bool, error) {
	if err := ValidateAccount(account); err != nil {
		return false, err
	}
	err := keychain.DeleteItem(genericPassword(account))
	if errors.Is(err, keychain.ErrorItemNotFound) {
		return false, nil
	}
	if err != nil {
		return false, &BackendError{Message: err.Error()}
	}
	return true, nil
}
