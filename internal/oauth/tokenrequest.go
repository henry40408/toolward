package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
)

// errInvalidGrant is the answer of a token endpoint that refuses the code or
// the refresh token.
var errInvalidGrant = errors.New("invalid_grant")

// tokenRequest is one request to the token endpoint. Action ("exchange" or
// "refresh") only names the request in errors.
type tokenRequest struct {
	Metadata    AuthorizationMetadata
	Credentials ClientCredentials
	Form        url.Values
	Action      string
}

// requestTokens sends the request and reads the tokens of the answer. client
// must not follow redirects.
func requestTokens(ctx context.Context, client *http.Client, request tokenRequest) (*TokenResponse, error) {
	httpRequest, err := newTokenHTTPRequest(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("OAuth token %s failed: %w", request.Action, err)
	}
	answer, err := send(client, httpRequest)
	if err != nil {
		return nil, fmt.Errorf("OAuth token %s failed: %w", request.Action, err)
	}
	return parseTokenAnswer(answer, request.Action)
}

func newTokenHTTPRequest(ctx context.Context, request tokenRequest) (*http.Request, error) {
	form := url.Values{}
	for key, values := range request.Form {
		form[key] = values
	}
	style := authStyle(request.Metadata, request.Credentials)
	secret := request.Credentials.ClientSecret
	if secret == nil || style == oauth2.AuthStyleInParams {
		form.Set("client_id", request.Credentials.ClientID)
	}
	if secret != nil && style == oauth2.AuthStyleInParams {
		form.Set("client_secret", *secret)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, request.Metadata.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpRequest.Header.Set("Accept", "application/json")
	if secret != nil && style == oauth2.AuthStyleInHeader {
		httpRequest.SetBasicAuth(url.QueryEscape(request.Credentials.ClientID), url.QueryEscape(*secret))
	}
	return httpRequest, nil
}

// parseTokenAnswer reads the answer of the token endpoint.
func parseTokenAnswer(answer *response, action string) (*TokenResponse, error) {
	if answer.Status >= 200 && answer.Status <= 299 {
		tokens, err := ParseTokenResponse(jsonBody(answer))
		if err != nil {
			return nil, fmt.Errorf("OAuth token %s failed: Server returned invalid response", action)
		}
		return &tokens, nil
	}
	var failure struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(jsonBody(answer), &failure)
	if failure.Error == "invalid_grant" {
		return nil, fmt.Errorf("OAuth token %s failed: %w", action, errInvalidGrant)
	}
	return nil, fmt.Errorf("OAuth token %s failed: Server returned error response (HTTP %d): %s", action, answer.Status, answer.Body)
}

// jsonBody returns the body as JSON. Some servers answer in form encoding
// (GitHub does without an Accept header). expires_in must stay a number.
func jsonBody(answer *response) []byte {
	mediaType, _, _ := mime.ParseMediaType(answer.Header.Get("Content-Type"))
	if mediaType != "application/x-www-form-urlencoded" && mediaType != "text/plain" {
		return answer.Body
	}
	values, err := url.ParseQuery(string(answer.Body))
	if err != nil {
		return answer.Body
	}
	fields := make(map[string]any, len(values))
	for key, list := range values {
		fields[key] = formValue(key, list[0])
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return answer.Body
	}
	return encoded
}

func formValue(key, value string) any {
	if key != "expires_in" {
		return value
	}
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		return seconds
	}
	return value
}
