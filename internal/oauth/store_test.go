package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/henry40408/toolward/internal/store"
)

func newTokens() (*store.Memory, *TokenStore) {
	memory := store.NewMemory()
	return memory, NewTokenStore(memory, "oauth.sentry")
}

func TestTokenValuesListsBothTokens(t *testing.T) {
	var credentials StoredCredentials
	text := `{"client_id":"c","token_response":{"access_token":"AT-1234","token_type":"Bearer","refresh_token":"RT-5678"},"granted_scopes":[]}`
	if err := json.Unmarshal([]byte(text), &credentials); err != nil {
		t.Fatal(err)
	}
	if got := credentials.Values(); !slices.Equal(got, []string{"AT-1234", "RT-5678"}) {
		t.Fatalf("got %v", got)
	}
	if got := (&StoredCredentials{ClientID: "c"}).Values(); got != nil {
		t.Fatalf("got %v", got)
	}
}

func TestAccountNames(t *testing.T) {
	got, err := AccountFor("sentry")
	if err != nil || got != "oauth.sentry" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := AccountFor("a/b"); err == nil {
		t.Fatal("a/b must be refused")
	}
}

func TestClientAccountNames(t *testing.T) {
	got, err := ClientAccountFor("sentry")
	if err != nil || got != "oauth-client.sentry" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := ClientAccountFor("a/b"); err == nil {
		t.Fatal("a/b must be refused")
	}
	if store.ValidateUserAccount("oauth-client.sentry") == nil {
		t.Fatal("the client account is reserved")
	}
}

func TestTokenStoreRoundTripAndClear(t *testing.T) {
	memory, tokens := newTokens()
	if loaded, err := tokens.Load(); err != nil || loaded != nil {
		t.Fatalf("empty store: %v, %v", loaded, err)
	}
	saved := &StoredCredentials{ClientID: "client-1", GrantedScopes: []string{"a"}}
	if err := tokens.Save(saved); err != nil {
		t.Fatal(err)
	}
	loaded, err := tokens.Load()
	if err != nil || loaded == nil || loaded.ClientID != "client-1" {
		t.Fatalf("got %v, %v", loaded, err)
	}
	if _, found, _ := memory.Get("oauth.sentry"); !found {
		t.Fatal("the record is stored")
	}
	if err := tokens.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := memory.Get("oauth.sentry"); found {
		t.Fatal("the record is cleared")
	}
}

func TestSaveTellsTheCallbackAboutBothTokens(t *testing.T) {
	_, tokens := newTokens()
	var told []string
	tokens.OnSave(func(values []string) { told = values })
	refresh := "RT-5678"
	saved := &StoredCredentials{ClientID: "c", TokenResponse: &TokenResponse{
		AccessToken: "AT-1234", TokenType: "bearer", RefreshToken: &refresh,
	}}
	if err := tokens.Save(saved); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(told, []string{"AT-1234", "RT-5678"}) {
		t.Fatalf("got %v", told)
	}
}

func TestUnreadableTokensDoNotLeakIntoTheError(t *testing.T) {
	cases := []string{"SECRETJUNK", `{"client_id":987654321}`, `{"client_id":"c","token_response":{"access_token":"SECRETJUNK"}}`}
	for _, text := range cases {
		memory, tokens := newTokens()
		_ = memory.Set("oauth.sentry", text)
		_, err := tokens.Load()
		if !errors.Is(err, ErrUnreadableTokens) || strings.Contains(err.Error(), "SECRETJUNK") || strings.Contains(err.Error(), "987654321") {
			t.Fatalf("%s: got %v", text, err)
		}
	}
}

func TestRustRecordsAreReadAndWrittenInTheSameShape(t *testing.T) {
	memory, tokens := newTokens()
	rust := `{"client_id":"c1","token_response":{"access_token":"AT","token_type":"bearer","expires_in":3600,"refresh_token":"RT","scope":"a b","vendor":{"x":1}},"granted_scopes":["a","b"],"token_received_at":1700000000,"issuer":"https://as.example"}`
	_ = memory.Set("oauth.sentry", rust)
	loaded, err := tokens.Load()
	if err != nil {
		t.Fatal(err)
	}
	response := loaded.TokenResponse
	if *response.ExpiresIn != 3600 || !slices.Equal(response.Scopes, []string{"a", "b"}) || *loaded.TokenReceivedAt != 1700000000 || *loaded.Issuer != "https://as.example" {
		t.Fatalf("got %+v", loaded)
	}
	if err := tokens.Save(loaded); err != nil {
		t.Fatal(err)
	}
	written, _, _ := memory.Get("oauth.sentry")
	want := `{"client_id":"c1","token_response":{"access_token":"AT","token_type":"bearer","expires_in":3600,"refresh_token":"RT","scope":"a b","vendor":{"x":1}},"granted_scopes":["a","b"],"token_received_at":1700000000,"issuer":"https://as.example"}`
	if written != want {
		t.Fatalf("got %s", written)
	}
}

func TestRecordsWithoutOptionalFieldsAreRead(t *testing.T) {
	memory, tokens := newTokens()
	_ = memory.Set("oauth.sentry", `{"client_id":"c1","token_response":{"access_token":"AT","token_type":"Bearer"}}`)
	loaded, err := tokens.Load()
	if err != nil || loaded.TokenResponse.TokenType != "bearer" || loaded.GrantedScopes == nil || loaded.TokenReceivedAt != nil {
		t.Fatalf("got %+v, %v", loaded, err)
	}
	_ = memory.Set("oauth.sentry", `{"client_id":"c1","token_response":null}`)
	loaded, err = tokens.Load()
	if err != nil || loaded.TokenResponse != nil {
		t.Fatalf("got %+v, %v", loaded, err)
	}
}

func TestLoginStateAndLogout(t *testing.T) {
	secrets := store.NewMemory()
	if in, err := IsLoggedIn(secrets, "sentry"); err != nil || in {
		t.Fatalf("got %v, %v", in, err)
	}
	_ = secrets.Set("oauth.sentry", "{}")
	if in, err := IsLoggedIn(secrets, "sentry"); err != nil || !in {
		t.Fatalf("got %v, %v", in, err)
	}
	if had, err := Logout(secrets, "sentry"); err != nil || !had {
		t.Fatalf("got %v, %v", had, err)
	}
	if had, err := Logout(secrets, "sentry"); err != nil || had {
		t.Fatalf("got %v, %v", had, err)
	}
	if _, err := IsLoggedIn(secrets, "a/b"); err == nil {
		t.Fatal("a/b must be refused")
	}
}

func TestLogoutRemovesTokensAndClientRecord(t *testing.T) {
	secrets := store.NewMemoryWith(map[string]string{
		"oauth.sentry": "{}", "oauth-client.sentry": "{}", "oauth-client.other": "{}",
	})
	if had, err := Logout(secrets, "sentry"); err != nil || !had {
		t.Fatalf("got %v, %v", had, err)
	}
	for account, want := range map[string]bool{"oauth.sentry": false, "oauth-client.sentry": false, "oauth-client.other": true} {
		if _, found, _ := secrets.Get(account); found != want {
			t.Fatalf("%s: found %v", account, found)
		}
	}
	_ = secrets.Set("oauth-client.sentry", "{}")
	if had, _ := Logout(secrets, "sentry"); !had {
		t.Fatal("a lone client record counts")
	}
	if had, _ := Logout(secrets, "sentry"); had {
		t.Fatal("nothing is left")
	}
}

// failingDelete is a store whose deletes of one account fail.
type failingDelete struct {
	*store.Memory
	account string
}

func (s failingDelete) Delete(account string) (bool, error) {
	if account == s.account {
		return false, fmt.Errorf("boom")
	}
	return s.Memory.Delete(account)
}

func TestFailedRecordDeleteKeepsTheTokens(t *testing.T) {
	secrets := failingDelete{Memory: store.NewMemory(), account: "oauth-client.sentry"}
	_ = secrets.Set("oauth.sentry", "{}")
	_ = secrets.Set("oauth-client.sentry", "{}")
	if _, err := Logout(secrets, "sentry"); err == nil {
		t.Fatal("the failure must be reported")
	}
	if _, found, _ := secrets.Get("oauth.sentry"); !found {
		t.Fatal("the tokens must stay")
	}
}

func TestRefreshLockSerializes(t *testing.T) {
	_, tokens := newTokens()
	unlock := tokens.LockRefresh()
	acquired := make(chan struct{})
	go func() {
		tokens.LockRefresh()()
		close(acquired)
	}()
	select {
	case <-acquired:
		t.Fatal("the second lock must wait")
	default:
	}
	unlock()
	<-acquired
}
