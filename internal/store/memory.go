package store

import "sync"

// Memory is an in-memory store for tests.
type Memory struct {
	mu      sync.Mutex
	secrets map[string]string
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{secrets: map[string]string{}}
}

// NewMemoryWith returns a store holding the given account to secret entries.
// It panics on an invalid account, so it is for tests only.
func NewMemoryWith(entries map[string]string) *Memory {
	m := NewMemory()
	for account, secret := range entries {
		if err := m.Set(account, secret); err != nil {
			panic(err)
		}
	}
	return m
}

func (m *Memory) Get(account string) (string, bool, error) {
	if err := ValidateAccount(account); err != nil {
		return "", false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	secret, ok := m.secrets[account]
	return secret, ok, nil
}

func (m *Memory) Set(account, secret string) error {
	if err := ValidateAccount(account); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[account] = secret
	return nil
}

func (m *Memory) Delete(account string) (bool, error) {
	if err := ValidateAccount(account); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.secrets[account]
	delete(m.secrets, account)
	return ok, nil
}
