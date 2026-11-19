package oauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http/httpproxy"
)

const (
	oauthHTTPTimeout   = 30 * time.Second
	maxOAuthBodyBytes  = 1 << 20
	maxOAuthRedirects  = 10
	discoveryProtocol  = "2024-11-05"
	protocolHeaderName = "MCP-Protocol-Version"
)

// HTTPClients are the clients of the OAuth requests of one server. Neither is
// the client of the MCP traffic.
type HTTPClients struct {
	// Stop returns redirects as they are. Token requests use it.
	Stop *http.Client
	// Follow follows up to 10 redirects. Registration uses it.
	Follow *http.Client
}

// NewHTTPClients returns clients that refuse addresses the resource must not
// reach (see addressPolicy). base is the URL of the MCP server.
func NewHTTPClients(base *url.URL) *HTTPClients {
	transport := newGuardedTransport(base, httpproxy.FromEnvironment())
	return &HTTPClients{
		Stop: &http.Client{
			Transport:     transport,
			Timeout:       oauthHTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		Follow: &http.Client{
			Transport: transport,
			Timeout:   oauthHTTPTimeout,
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) > maxOAuthRedirects {
					return fmt.Errorf("OAuth request exceeded %d redirects", maxOAuthRedirects)
				}
				return nil
			},
		},
	}
}

// response is a fully read answer.
type response struct {
	Status int
	Header http.Header
	Body   []byte
}

// send runs a request and reads at most 1 MiB of its body.
func send(client *http.Client, request *http.Request) (*response, error) {
	answer, err := client.Do(request)
	if err != nil {
		return nil, withoutURL(err)
	}
	defer func() { _ = answer.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(answer.Body, maxOAuthBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxOAuthBodyBytes {
		return nil, fmt.Errorf("OAuth HTTP response body exceeds %d bytes", maxOAuthBodyBytes)
	}
	return &response{Status: answer.StatusCode, Header: answer.Header, Body: body}, nil
}

// withoutURL drops the URL that net/http adds to its errors: it may hold a
// credential in its query.
func withoutURL(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

// discoveryGet fetches a metadata document. Redirects are followed only within
// the origin, and an answer that says the server is unwell is an error.
func discoveryGet(ctx context.Context, client *http.Client, target *url.URL) (*response, error) {
	current := target
	for range maxOAuthRedirects {
		answer, err := getOnce(ctx, client, current)
		if err != nil {
			return nil, err
		}
		if answer.Status < 300 || answer.Status > 399 {
			return answer, nil
		}
		location := answer.Header.Get("Location")
		if location == "" {
			return answer, nil
		}
		next, err := current.Parse(location)
		if err != nil {
			return nil, err
		}
		if !isHTTPURL(next) || !sameOrigin(current, next) {
			return nil, fmt.Errorf("OAuth discovery redirect to non-same-origin URL rejected: %s", next)
		}
		current = next
	}
	return nil, fmt.Errorf("OAuth request exceeded %d redirects", maxOAuthRedirects)
}

func getOnce(ctx context.Context, client *http.Client, target *url.URL) (*response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set(protocolHeaderName, discoveryProtocol)
	answer, err := send(client, request)
	if err != nil {
		return nil, err
	}
	if isUnwell(answer.Status) {
		return nil, fmt.Errorf("unexpected HTTP status %d", answer.Status)
	}
	return answer, nil
}

func isUnwell(status int) bool {
	return status >= 500 || status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests
}
