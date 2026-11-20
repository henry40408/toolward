// Package check builds the report of `toolward check`: one block per server.
//
// The checks collect plain facts into ServerReports. RenderText turns them
// into text for people and RenderJSON into JSON for programs; the two have
// different readers and share only the facts.
package check

import (
	"maps"
	"slices"

	"github.com/henry40408/toolward/internal/config"
	"github.com/henry40408/toolward/internal/oauth"
	"github.com/henry40408/toolward/internal/store"
)

// SecretStatus tells whether a secret is in the credential store.
type SecretStatus string

const (
	SecretOK      SecretStatus = "ok"
	SecretMissing SecretStatus = "missing"
	SecretError   SecretStatus = "error"
)

// SecretReport tells whether one secret is in the credential store. It holds
// no secret value.
type SecretReport struct {
	// Account is the credential store entry, as in `${keychain:<account>}`.
	Account string       `json:"account"`
	Status  SecretStatus `json:"status"`
	Reason  string       `json:"reason,omitempty"`
}

// OAuthStatus tells whether a server has a stored login.
type OAuthStatus string

const (
	OAuthLoggedIn    OAuthStatus = "logged_in"
	OAuthNotLoggedIn OAuthStatus = "not_logged_in"
	OAuthError       OAuthStatus = "error"
)

// OAuthReport is the login state of a server that uses OAuth.
type OAuthReport struct {
	Status OAuthStatus `json:"status"`
	Reason string      `json:"reason,omitempty"`
}

// ToolReport is one tool of an upstream.
type ToolReport struct {
	// Name is what the agent sees, with the `<server>__` prefix.
	Name string `json:"name"`
	// Original is the name the upstream server gave it.
	Original string `json:"original"`
}

// UpstreamReport is what connecting to the upstream showed. Failed is set
// when the connection or the listing failed; then only Reason is meaningful.
type UpstreamReport struct {
	Failed bool
	Reason string
	// Protocol and Server are nil when the upstream did not announce them.
	Protocol     *string
	Server       *string
	Capabilities []string
	Tools        []ToolReport
}

// ServerReport is the block of one server.
type ServerReport struct {
	Name    string
	Secrets []SecretReport
	// OAuth is nil when the server does not use OAuth.
	OAuth *OAuthReport
	// Upstream is nil until CheckTools ran.
	Upstream *UpstreamReport
}

func newServerReport(name string) *ServerReport {
	return &ServerReport{Name: name, Secrets: []SecretReport{}}
}

// OK says whether nothing about the server is a problem.
func (r *ServerReport) OK() bool {
	for _, secret := range r.Secrets {
		if secret.Status != SecretOK {
			return false
		}
	}
	if r.OAuth != nil && r.OAuth.Status != OAuthLoggedIn {
		return false
	}
	return r.Upstream == nil || !r.Upstream.Failed
}

// AllOK says whether every server is ok.
func AllOK(reports []*ServerReport) bool {
	return !slices.ContainsFunc(reports, func(report *ServerReport) bool { return !report.OK() })
}

// CheckSecrets checks that every referenced secret and OAuth login is in the
// store. It never reads a secret value into the report.
func CheckSecrets(cfg *config.Config, secrets store.Store) []*ServerReport {
	references := cfg.References()
	servers := slices.Sorted(maps.Keys(references))
	oauthServers := cfg.OAuthServers()
	reports := make([]*ServerReport, 0, len(servers))
	for _, server := range servers {
		report := newServerReport(server)
		if slices.Contains(oauthServers, server) {
			report.OAuth = oauthReport(secrets, server)
		}
		for _, account := range references[server] {
			report.Secrets = append(report.Secrets, secretReport(secrets, account))
		}
		reports = append(reports, report)
	}
	return reports
}

func oauthReport(secrets store.Store, server string) *OAuthReport {
	loggedIn, err := oauth.IsLoggedIn(secrets, server)
	switch {
	case err != nil:
		return &OAuthReport{Status: OAuthError, Reason: err.Error()}
	case loggedIn:
		return &OAuthReport{Status: OAuthLoggedIn}
	}
	return &OAuthReport{Status: OAuthNotLoggedIn}
}

func secretReport(secrets store.Store, account string) SecretReport {
	_, found, err := secrets.Get(account)
	switch {
	case err != nil:
		return SecretReport{Account: account, Status: SecretError, Reason: err.Error()}
	case found:
		return SecretReport{Account: account, Status: SecretOK}
	}
	return SecretReport{Account: account, Status: SecretMissing}
}
