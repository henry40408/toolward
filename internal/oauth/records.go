package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/henry40408/toolward/internal/store"
)

const (
	unreadableRecord = "the stored OAuth client record is unreadable; run `toolward auth login` again"
	maskedSecret     = "[REDACTED]"
)

// ClientRecord is the client that `auth login` registered dynamically. It
// lives in its own account because the token record has no room for a client
// secret. It is written only after the tokens, so the two agree on the client
// id.
type ClientRecord struct {
	ClientID string `json:"client_id"`
	// ClientSecret is nil for a public client. It is written as null then, as
	// the Rust version did.
	ClientSecret *string `json:"client_secret"`
}

// String hides the secret.
func (r ClientRecord) String() string {
	secret := "none"
	if r.ClientSecret != nil {
		secret = maskedSecret
	}
	return fmt.Sprintf("ClientRecord{client_id: %q, client_secret: %s}", r.ClientID, secret)
}

// GoString is String too, so %#v cannot show the secret.
func (r ClientRecord) GoString() string { return r.String() }

// UnmarshalJSON requires the client id. The error text never holds the input.
func (r *ClientRecord) UnmarshalJSON(data []byte) error {
	var wire struct {
		ClientID     *string `json:"client_id"`
		ClientSecret *string `json:"client_secret"`
	}
	if json.Unmarshal(data, &wire) != nil || wire.ClientID == nil {
		return errors.New("invalid client record")
	}
	*r = ClientRecord{ClientID: *wire.ClientID, ClientSecret: wire.ClientSecret}
	return nil
}

// ReadClientRecord reads the record. Error text never contains it.
func ReadClientRecord(secrets store.Store, server string) (*ClientRecord, error) {
	account, err := ClientAccountFor(server)
	if err != nil {
		return nil, err
	}
	text, found, err := secrets.Get(account)
	if err != nil || !found {
		return nil, err
	}
	var record ClientRecord
	if json.Unmarshal([]byte(text), &record) != nil {
		return nil, errors.New(unreadableRecord)
	}
	return &record, nil
}

// ReadClientRecordLenient is like ReadClientRecord, but an unreadable record
// counts as absent, with a warning that holds no content.
func ReadClientRecordLenient(secrets store.Store, server string, log io.Writer) *ClientRecord {
	record, err := ReadClientRecord(secrets, server)
	if err == nil {
		return record
	}
	if log != nil {
		fmt.Fprintf(log, "toolward: ignoring the unreadable OAuth client record of %q; run `toolward auth login %s` if refreshing fails\n", server, server)
	}
	return nil
}

// RegistrationRecord is the record to keep after a dynamic registration. A
// public client has no secret, so nothing is kept.
func RegistrationRecord(clientID string, clientSecret *string) *ClientRecord {
	if clientSecret == nil {
		return nil
	}
	return &ClientRecord{ClientID: clientID, ClientSecret: clientSecret}
}

// WriteClientRecord stores the record, or removes it when record is nil.
func WriteClientRecord(secrets store.Store, server string, record *ClientRecord) error {
	account, err := ClientAccountFor(server)
	if err != nil {
		return err
	}
	if record == nil {
		_, err := secrets.Delete(account)
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return errors.New("cannot encode the OAuth client record")
	}
	return secrets.Set(account, string(encoded))
}

// ResolveClientSecret picks the client secret for refreshing and lists what
// to mask. A configured secret wins. A stored one counts only for the client
// the tokens belong to. Every stored secret is masked, matching or not.
func ResolveClientSecret(configured *string, record *ClientRecord, tokenClientID string) (used *string, mask []string) {
	if record != nil && record.ClientSecret != nil {
		mask = []string{*record.ClientSecret}
	}
	if configured != nil {
		return configured, mask
	}
	if record != nil && record.ClientID == tokenClientID {
		return record.ClientSecret, mask
	}
	return nil, mask
}
