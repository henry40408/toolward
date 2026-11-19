//go:build darwin

package store

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestBackendErrorExplainsAnItemOfAnotherBuild(t *testing.T) {
	err := backendError("github-token", errSecInvalidOwnerEdit)
	for _, want := range []string{"another build", "security delete-generic-password -s toolward -a github-token", "toolward secret set github-token"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks %q: %v", want, err)
		}
	}
	if other := backendError("a", errors.New("boom")); !strings.Contains(other.Error(), "boom") || strings.Contains(other.Error(), "another build") {
		t.Errorf("got %v", other)
	}
}

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
	t.Cleanup(func() { _, _ = kc.Delete(account) })
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

// A bad account is refused before any Keychain call, so no prompt can appear.
func TestKeychainRejectsBadAccount(t *testing.T) {
	var target *InvalidAccountError
	if err := (&Keychain{}).Set("bad/name", "x"); !errors.As(err, &target) {
		t.Fatalf("Set: got %v", err)
	}
	if _, _, err := (&Keychain{}).Get("bad/name"); !errors.As(err, &target) {
		t.Fatalf("Get: got %v", err)
	}
	if _, err := (&Keychain{}).Delete("bad/name"); !errors.As(err, &target) {
		t.Fatalf("Delete: got %v", err)
	}
}
