package interpolate

import (
	"errors"
	"slices"
	"testing"

	"github.com/henry40408/toolward/internal/store"
)

func testStore() store.Store {
	return store.NewMemoryWith(map[string]string{"gh": "ghp_abc", "b": "B"})
}

func TestPlainStringsPassThrough(t *testing.T) {
	for _, input := range []string{"hello $ world $5", ""} {
		got, err := Expand(input, testStore())
		if err != nil || got != input {
			t.Errorf("Expand(%q) = %q, %v", input, got, err)
		}
	}
}

func TestExpandsReferencesInline(t *testing.T) {
	tests := map[string]string{
		"Bearer ${keychain:gh}":         "Bearer ghp_abc",
		"${keychain:gh}:${keychain:b}!": "ghp_abc:B!",
	}
	for input, want := range tests {
		got, err := Expand(input, testStore())
		if err != nil || got != want {
			t.Errorf("Expand(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
}

func TestEscapeYieldsALiteral(t *testing.T) {
	got, err := Expand("$${keychain:gh}", testStore())
	if err != nil || got != "${keychain:gh}" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestSecretValueIsNotReinterpreted(t *testing.T) {
	s := store.NewMemoryWith(map[string]string{"x": "${keychain:y}"})
	got, err := Expand("${keychain:x}", s)
	if err != nil || got != "${keychain:y}" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestRejectsUnsupportedAndMalformed(t *testing.T) {
	if _, err := Expand("${HOME}", testStore()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("${HOME}: %v", err)
	}
	if _, err := Expand("${keychain:gh", testStore()); !errors.Is(err, ErrUnterminated) {
		t.Errorf("unterminated: %v", err)
	}
	var invalid *store.InvalidAccountError
	if _, err := Expand("${keychain:bad name}", testStore()); !errors.As(err, &invalid) {
		t.Errorf("bad account: %v", err)
	}
}

func TestReservedAccountsCannotBeReferenced(t *testing.T) {
	var reserved *store.ReservedAccountError
	if _, err := References("${keychain:oauth.x}"); !errors.As(err, &reserved) {
		t.Fatalf("got %v", err)
	}
}

func TestMissingSecretNamesTheAccount(t *testing.T) {
	_, err := Expand("${keychain:nope}", testStore())
	var missing *MissingError
	if !errors.As(err, &missing) || missing.Account != "nope" {
		t.Fatalf("got %v", err)
	}
	want := "no secret stored for account \"nope\"; run `toolward secret set nope`"
	if err.Error() != want {
		t.Fatalf("message = %q", err.Error())
	}
}

func TestListsReferencesWithoutTouchingTheStore(t *testing.T) {
	got, err := References("a ${keychain:x} $${keychain:no} ${keychain:y}")
	if err != nil || !slices.Equal(got, []string{"x", "y"}) {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestExpandCollectingReturnsTheSubstitutedSecrets(t *testing.T) {
	out, secrets, err := ExpandCollecting("${keychain:gh}/${keychain:b}", testStore())
	if err != nil || out != "ghp_abc/B" {
		t.Fatalf("got %q, %v", out, err)
	}
	if !slices.Equal(secrets, []string{"ghp_abc", "B"}) {
		t.Fatalf("secrets = %v", secrets)
	}
}
