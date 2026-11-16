package oauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/henry40408/toolward/internal/store"
)

// TokenResponse is the token response of an authorization server, in the JSON
// shape the Rust version stored (rmcp's StandardTokenResponse with the extra
// fields kept).
type TokenResponse struct {
	AccessToken string
	// TokenType is lowercase, as the Rust version wrote it.
	TokenType string
	// ExpiresIn is in seconds. Nil when the server did not say.
	ExpiresIn    *uint64
	RefreshToken *string
	// Scopes is nil when the response had no "scope".
	Scopes []string
	// Extra holds the fields this program does not use. They are kept so a
	// record survives a round trip.
	Extra map[string]json.RawMessage
}

var tokenResponseKeys = []string{"access_token", "token_type", "expires_in", "refresh_token", "scope"}

type tokenResponseWire struct {
	AccessToken  *string `json:"access_token"`
	TokenType    *string `json:"token_type"`
	ExpiresIn    *uint64 `json:"expires_in"`
	RefreshToken *string `json:"refresh_token"`
	Scope        *string `json:"scope"`
}

// UnmarshalJSON reads the stored shape. Its error never holds the input.
func (t *TokenResponse) UnmarshalJSON(data []byte) error {
	return t.decode(data, "")
}

// ParseTokenResponse reads the body of a token endpoint. A server may leave
// out token_type, which then is bearer.
func ParseTokenResponse(body []byte) (TokenResponse, error) {
	var response TokenResponse
	err := response.decode(body, "bearer")
	return response, err
}

// decode reads a token response. defaultType is used when the input has no
// token_type; with "" such an input is an error.
func (t *TokenResponse) decode(data []byte, defaultType string) error {
	var wire tokenResponseWire
	var all map[string]json.RawMessage
	if json.Unmarshal(data, &wire) != nil || json.Unmarshal(data, &all) != nil {
		return errors.New("invalid token response")
	}
	if wire.TokenType == nil && defaultType != "" {
		wire.TokenType = &defaultType
	}
	if wire.AccessToken == nil || wire.TokenType == nil {
		return errors.New("invalid token response")
	}
	*t = TokenResponse{
		AccessToken:  *wire.AccessToken,
		TokenType:    strings.ToLower(*wire.TokenType),
		ExpiresIn:    wire.ExpiresIn,
		RefreshToken: wire.RefreshToken,
	}
	if wire.Scope != nil {
		t.Scopes = strings.Fields(*wire.Scope)
	}
	for _, key := range tokenResponseKeys {
		delete(all, key)
	}
	if len(all) > 0 {
		t.Extra = all
	}
	return nil
}

// MarshalJSON writes the standard fields in the order of the Rust version,
// then the extra fields sorted by name.
func (t TokenResponse) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	writeMember(&buf, "access_token", t.AccessToken)
	writeMember(&buf, "token_type", t.TokenType)
	if t.ExpiresIn != nil {
		writeMember(&buf, "expires_in", *t.ExpiresIn)
	}
	if t.RefreshToken != nil {
		writeMember(&buf, "refresh_token", *t.RefreshToken)
	}
	if t.Scopes != nil {
		writeMember(&buf, "scope", strings.Join(t.Scopes, " "))
	}
	for _, key := range sortedExtraKeys(t.Extra) {
		writeMember(&buf, key, t.Extra[key])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func sortedExtraKeys(extra map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(extra))
	for key := range extra {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func writeMember(buf *bytes.Buffer, key string, value any) {
	if buf.Len() > 1 {
		buf.WriteByte(',')
	}
	name, _ := json.Marshal(key)
	encoded, _ := json.Marshal(value)
	buf.Write(name)
	buf.WriteByte(':')
	buf.Write(encoded)
}

// StoredCredentials is the token record, in the JSON shape the Rust version
// wrote, so existing logins keep working.
type StoredCredentials struct {
	ClientID      string         `json:"client_id"`
	TokenResponse *TokenResponse `json:"token_response"`
	GrantedScopes []string       `json:"granted_scopes"`
	// TokenReceivedAt is in Unix seconds.
	TokenReceivedAt *uint64 `json:"token_received_at"`
	Issuer          *string `json:"issuer"`
}

// UnmarshalJSON requires the client id. The error never holds the input.
func (c *StoredCredentials) UnmarshalJSON(data []byte) error {
	type plain StoredCredentials
	var wire struct {
		ClientID *string `json:"client_id"`
		plain
	}
	if json.Unmarshal(data, &wire) != nil || wire.ClientID == nil {
		return errors.New("invalid credentials")
	}
	*c = StoredCredentials(wire.plain)
	c.ClientID = *wire.ClientID
	if c.GrantedScopes == nil {
		c.GrantedScopes = []string{}
	}
	return nil
}

// Values returns the access and refresh token, for redaction.
func (c *StoredCredentials) Values() []string {
	if c == nil || c.TokenResponse == nil {
		return nil
	}
	values := []string{c.TokenResponse.AccessToken}
	if c.TokenResponse.RefreshToken != nil {
		values = append(values, *c.TokenResponse.RefreshToken)
	}
	return values
}

// ErrUnreadableTokens is the failure for a record that cannot be decoded. Its
// text never contains the record.
var ErrUnreadableTokens = errors.New("the stored OAuth tokens are unreadable; run `toolward auth login` again")

// TokenStore keeps a server's token record as one JSON entry in the
// credential store. Error text never contains the record.
type TokenStore struct {
	store   store.Store
	account string
	// refresh serializes refreshes within this process.
	refresh sync.Mutex
	// onSave is told about the tokens of every record saved, so they can be
	// masked.
	onSave func(tokens []string)
}

// NewTokenStore returns the token store of account.
func NewTokenStore(secrets store.Store, account string) *TokenStore {
	return &TokenStore{store: secrets, account: account}
}

// OnSave registers the callback for the tokens of every saved record.
func (s *TokenStore) OnSave(callback func(tokens []string)) *TokenStore {
	s.onSave = callback
	return s
}

// Load returns nil when nothing is stored.
func (s *TokenStore) Load() (*StoredCredentials, error) {
	text, found, err := s.store.Get(s.account)
	if err != nil {
		return nil, credentialStoreError(err)
	}
	if !found {
		return nil, nil
	}
	var credentials StoredCredentials
	if json.Unmarshal([]byte(text), &credentials) != nil {
		return nil, ErrUnreadableTokens
	}
	return &credentials, nil
}

// Save stores the record and tells the OnSave callback about its tokens.
func (s *TokenStore) Save(credentials *StoredCredentials) error {
	encoded, err := json.Marshal(credentials)
	if err != nil {
		return errors.New("cannot encode OAuth tokens")
	}
	if err := s.store.Set(s.account, string(encoded)); err != nil {
		return credentialStoreError(err)
	}
	if s.onSave != nil {
		s.onSave(credentials.Values())
	}
	return nil
}

// Clear removes the record.
func (s *TokenStore) Clear() error {
	if _, err := s.store.Delete(s.account); err != nil {
		return credentialStoreError(err)
	}
	return nil
}

// LockRefresh takes the refresh lock and returns the function that releases
// it. A refresh must load, exchange and save while holding it.
func (s *TokenStore) LockRefresh() (unlock func()) {
	s.refresh.Lock()
	return s.refresh.Unlock
}

func credentialStoreError(err error) error {
	return fmt.Errorf("OAuth credential store failed: %w", err)
}
