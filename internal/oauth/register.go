package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	clientName      = "toolward"
	applicationType = "native"
)

// RegisteredClient is what a server issued by dynamic client registration.
type RegisteredClient struct {
	ClientID string
	// ClientSecret is nil for a public client.
	ClientSecret *string
}

// RegistrationRequest describes the client to register.
type RegistrationRequest struct {
	RedirectURI string
	Scopes      []string
}

type registrationBody struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope,omitempty"`
	ApplicationType         string   `json:"application_type"`
}

// Register registers toolward as a public client (RFC 7591). Error text may
// hold server text, so callers mask it.
func Register(ctx context.Context, client *http.Client, metadata AuthorizationMetadata, request RegistrationRequest) (*RegisteredClient, error) {
	if metadata.RegistrationEndpoint == nil {
		return nil, errors.New("Registration failed: Dynamic client registration not supported")
	}
	if err := metadata.ValidateForCodeFlow(); err != nil {
		return nil, err
	}
	body, err := registrationJSON(request)
	if err != nil {
		return nil, fmt.Errorf("Registration failed: %w", err)
	}
	answer, err := postRegistration(ctx, client, *metadata.RegistrationEndpoint, body)
	if err != nil {
		return nil, err
	}
	return parseRegistration(answer)
}

func registrationJSON(request RegistrationRequest) ([]byte, error) {
	return json.Marshal(registrationBody{
		ClientName:              clientName,
		RedirectURIs:            []string{request.RedirectURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "none",
		ResponseTypes:           []string{"code"},
		Scope:                   strings.Join(request.Scopes, " "),
		ApplicationType:         applicationType,
	})
}

func postRegistration(ctx context.Context, client *http.Client, endpoint string, body []byte) (*response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("Registration failed: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	answer, err := send(client, request)
	if err != nil {
		return nil, fmt.Errorf("Registration failed: HTTP request error: %w", err)
	}
	if answer.Status < 200 || answer.Status > 299 {
		return nil, fmt.Errorf("Registration failed: HTTP %d %s: %s", answer.Status, http.StatusText(answer.Status), answer.Body)
	}
	return answer, nil
}

func parseRegistration(answer *response) (*RegisteredClient, error) {
	var wire struct {
		ClientID     *string   `json:"client_id"`
		ClientSecret *string   `json:"client_secret"`
		RedirectURIs *[]string `json:"redirect_uris"`
	}
	if json.Unmarshal(answer.Body, &wire) != nil || wire.ClientID == nil || wire.RedirectURIs == nil {
		return nil, errors.New("Registration failed: analyze response error")
	}
	registered := &RegisteredClient{ClientID: *wire.ClientID}
	// An empty secret means a public client. Sending it as a password would
	// authenticate with the client id alone.
	if wire.ClientSecret != nil && *wire.ClientSecret != "" {
		registered.ClientSecret = wire.ClientSecret
	}
	return registered, nil
}
