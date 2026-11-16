package oauth

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/henry40408/toolward/internal/store"
)

func ptr(text string) *string { return &text }

func TestClientRecordRoundTripHidesSecretInErrorsAndFormatting(t *testing.T) {
	secrets := store.NewMemory()
	if record, err := ReadClientRecord(secrets, "sentry"); err != nil || record != nil {
		t.Fatalf("got %v, %v", record, err)
	}
	record := &ClientRecord{ClientID: "c1", ClientSecret: ptr("CS-fake")}
	for _, text := range []string{fmt.Sprint(record), fmt.Sprintf("%v", *record), fmt.Sprintf("%#v", *record), fmt.Sprintf("%+v", *record)} {
		if strings.Contains(text, "CS-fake") {
			t.Fatalf("the secret is shown: %s", text)
		}
	}
	if err := WriteClientRecord(secrets, "sentry", record); err != nil {
		t.Fatal(err)
	}
	read, err := ReadClientRecord(secrets, "sentry")
	if err != nil || read.ClientID != "c1" || *read.ClientSecret != "CS-fake" {
		t.Fatalf("got %v, %v", read, err)
	}
	if err := WriteClientRecord(secrets, "sentry", &ClientRecord{ClientID: "c2"}); err != nil {
		t.Fatal(err)
	}
	read, _ = ReadClientRecord(secrets, "sentry")
	if read.ClientID != "c2" || read.ClientSecret != nil {
		t.Fatalf("got %v", read)
	}
	// Switching to a configured clientId removes the record.
	if err := WriteClientRecord(secrets, "sentry", nil); err != nil {
		t.Fatal(err)
	}
	if read, _ := ReadClientRecord(secrets, "sentry"); read != nil {
		t.Fatalf("got %v", read)
	}
}

func TestClientRecordIsWrittenLikeRust(t *testing.T) {
	secrets := store.NewMemory()
	_ = WriteClientRecord(secrets, "sentry", &ClientRecord{ClientID: "c1"})
	text, _, _ := secrets.Get("oauth-client.sentry")
	if text != `{"client_id":"c1","client_secret":null}` {
		t.Fatalf("got %s", text)
	}
}

func TestUnreadableClientRecordErrorHoldsNoContent(t *testing.T) {
	cases := []string{`{"client_id":"c1","client_secret":987654321}`, "not json CS-JUNK", `{"client_secret":"CS-JUNK"}`}
	for _, text := range cases {
		secrets := store.NewMemoryWith(map[string]string{"oauth-client.sentry": text})
		_, err := ReadClientRecord(secrets, "sentry")
		if err == nil || strings.Contains(err.Error(), "987654321") || strings.Contains(err.Error(), "JUNK") {
			t.Fatalf("%s: got %v", text, err)
		}
	}
}

func TestUnreadableRecordIsIgnoredByTheLenientReader(t *testing.T) {
	secrets := store.NewMemoryWith(map[string]string{"oauth-client.sentry": "not json CS-JUNK"})
	var log bytes.Buffer
	if ReadClientRecordLenient(secrets, "sentry", &log) != nil {
		t.Fatal("an unreadable record counts as absent")
	}
	want := "toolward: ignoring the unreadable OAuth client record of \"sentry\"; run `toolward auth login sentry` if refreshing fails\n"
	if log.String() != want {
		t.Fatalf("got %q", log.String())
	}
	_ = WriteClientRecord(secrets, "sentry", &ClientRecord{ClientID: "c1", ClientSecret: ptr("CS-fake")})
	if ReadClientRecordLenient(secrets, "sentry", nil) == nil {
		t.Fatal("a readable record is returned")
	}
}

func TestPublicClientRegistrationKeepsNoRecord(t *testing.T) {
	if RegistrationRecord("c1", nil) != nil {
		t.Fatal("a public client keeps nothing")
	}
	kept := RegistrationRecord("c1", ptr("CS-fake"))
	if kept == nil || *kept.ClientSecret != "CS-fake" {
		t.Fatalf("got %v", kept)
	}
	// nil clears an older record on a successful login.
	secrets := store.NewMemory()
	_ = WriteClientRecord(secrets, "sentry", &ClientRecord{ClientID: "old", ClientSecret: ptr("CS-old")})
	_ = WriteClientRecord(secrets, "sentry", RegistrationRecord("c1", nil))
	if _, found, _ := secrets.Get("oauth-client.sentry"); found {
		t.Fatal("the old record must be gone")
	}
}

func TestStoredSecretIsUsedOnlyForTheMatchingClient(t *testing.T) {
	record := &ClientRecord{ClientID: "c1", ClientSecret: ptr("CS-fake")}
	used, mask := ResolveClientSecret(nil, record, "c1")
	if used == nil || *used != "CS-fake" || len(mask) != 1 || mask[0] != "CS-fake" {
		t.Fatalf("got %v, %v", used, mask)
	}
	used, mask = ResolveClientSecret(nil, record, "other")
	if used != nil || len(mask) != 1 {
		t.Fatalf("a secret of another client is masked but not used: %v, %v", used, mask)
	}
	used, mask = ResolveClientSecret(nil, nil, "c1")
	if used != nil || len(mask) != 0 {
		t.Fatalf("got %v, %v", used, mask)
	}
	public := &ClientRecord{ClientID: "c1"}
	if used, _ := ResolveClientSecret(nil, public, "c1"); used != nil {
		t.Fatalf("got %v", used)
	}
}

func TestConfiguredSecretWinsOverTheStoredOne(t *testing.T) {
	record := &ClientRecord{ClientID: "c1", ClientSecret: ptr("CS-stored")}
	used, mask := ResolveClientSecret(ptr("CS-config"), record, "c1")
	if *used != "CS-config" || len(mask) != 1 || mask[0] != "CS-stored" {
		t.Fatalf("got %v, %v", *used, mask)
	}
}
