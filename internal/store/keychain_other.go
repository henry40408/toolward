//go:build !darwin

package store

// NewKeychain reports that this platform has no credential store.
func NewKeychain() (Store, error) {
	return nil, ErrUnsupported
}
