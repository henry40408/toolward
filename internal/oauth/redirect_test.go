package oauth

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestParseRedirectNamesTheMissingParameter(t *testing.T) {
	tests := map[string]string{
		"http://127.0.0.1/cb?state=s": "Authorization callback missing code",
		"http://127.0.0.1/cb?code=c":  "Authorization callback missing state",
		"http://[::1/cb":              "URL parse error",
	}
	for redirect, want := range tests {
		_, err := parseRedirect(redirect)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", redirect, err, want)
		}
	}
	parameters, err := parseRedirect("http://127.0.0.1/cb?code=c&state=s&iss=https%3A%2F%2Fa")
	if err != nil || parameters.code != "c" || parameters.state != "s" || parameters.issuer == nil || *parameters.issuer != "https://a" {
		t.Fatalf("got %+v, %v", parameters, err)
	}
}

func TestCompleteRefusesARedirectOfAnotherAuthorization(t *testing.T) {
	authorization := &Authorization{State: "expected"}
	_, err := authorization.Complete(context.Background(), http.DefaultClient, "http://127.0.0.1/cb?code=c&state=other")
	if err == nil || err.Error() != "Internal error: Authorization state not found" {
		t.Fatalf("got %v", err)
	}
}

func TestCompleteRefusesAnIssuerThatDiffers(t *testing.T) {
	issuer := "https://good.example"
	authorization := &Authorization{State: "s", request: AuthorizationRequest{Discovery: &Discovery{Metadata: AuthorizationMetadata{Issuer: &issuer}}}}
	_, err := authorization.Complete(context.Background(), http.DefaultClient, "http://127.0.0.1/cb?code=c&state=s&iss=https%3A%2F%2Fevil.example")
	if err == nil || !strings.Contains(err.Error(), "issuer mismatch: expected https://good.example, received https://evil.example") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateIssuerWithoutARecordedIssuer(t *testing.T) {
	received := "https://x.example"
	if err := validateIssuer(AuthorizationMetadata{}, &received); err == nil || !strings.Contains(err.Error(), "expected issuer was not recorded") {
		t.Fatalf("got %v", err)
	}
	if err := validateIssuer(AuthorizationMetadata{IssuerInResponse: true}, nil); err == nil {
		t.Fatal("a server that promises iss needs a recorded issuer")
	}
	if err := validateIssuer(AuthorizationMetadata{}, nil); err != nil {
		t.Fatal(err)
	}
	issuer := "https://x.example"
	if err := validateIssuer(AuthorizationMetadata{Issuer: &issuer, IssuerInResponse: true}, nil); err == nil || !strings.Contains(err.Error(), "missing required issuer") {
		t.Fatalf("got %v", err)
	}
	if err := validateIssuer(AuthorizationMetadata{Issuer: &issuer}, nil); err != nil {
		t.Fatal(err)
	}
}
