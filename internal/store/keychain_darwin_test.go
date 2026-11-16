//go:build darwin

package store

import (
	"os"
	"testing"
)

// The real Keychain may prompt, so this runs only on request.
func TestKeychainRoundTrip(t *testing.T) {
	if os.Getenv("TOOLWARD_KEYCHAIN_TEST") != "1" {
		t.Skip("set TOOLWARD_KEYCHAIN_TEST=1 to use the real Keychain")
	}
	kc, err := NewKeychain()
	if err != nil {
		t.Fatal(err)
	}
	account := "toolward-test-keychain-round-trip"
	t.Cleanup(func() { kc.Delete(account) })
	if _, found, err := kc.Get(account); found || err != nil {
		t.Fatalf("found=%v err=%v", found, err)
	}
	for _, secret := range []string{"s3cret", "replaced"} {
		if err := kc.Set(account, secret); err != nil {
			t.Fatal(err)
		}
		if got, found, err := kc.Get(account); !found || err != nil || got != secret {
			t.Fatalf("got %q %v %v", got, found, err)
		}
	}
	if removed, err := kc.Delete(account); !removed || err != nil {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
	if removed, _ := kc.Delete(account); removed {
		t.Fatal("second delete removed something")
	}
}
