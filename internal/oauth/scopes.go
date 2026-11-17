package oauth

import "slices"

const offlineAccess = "offline_access"

// ScopeHints are the scopes that discovery found. Choosing between them
// follows rmcp's `select_scopes`.
type ScopeHints struct {
	// Challenge is the scope of a WWW-Authenticate challenge that pointed to
	// the resource metadata.
	Challenge []string
	// Resource is the scopes_supported of the protected resource metadata.
	Resource []string
	// Supported is the scopes_supported of the authorization server metadata.
	Supported []string
}

// EffectiveScopes are the scopes for registration and authorization: the
// server-selected ones when none are configured, else the configured ones plus
// offline_access when the server supports it.
func EffectiveScopes(configured []string, hints ScopeHints) []string {
	if len(configured) == 0 {
		return selectScopes(hints)
	}
	return withOfflineAccess(slices.Clone(configured), hints.Supported)
}

// selectScopes takes what the resource asked for. Only when it asked for
// nothing, the scopes the authorization server supports are requested.
func selectScopes(hints ScopeHints) []string {
	asked := dedup(append(slices.Clone(hints.Challenge), hints.Resource...))
	if len(asked) == 0 {
		asked = slices.Clone(hints.Supported)
	}
	return withOfflineAccess(asked, hints.Supported)
}

// withOfflineAccess adds offline_access when the authorization server lists
// it, so servers that follow OIDC issue a refresh token.
func withOfflineAccess(scopes, supported []string) []string {
	if len(scopes) == 0 || slices.Contains(scopes, offlineAccess) {
		return scopes
	}
	if slices.Contains(supported, offlineAccess) {
		return append(scopes, offlineAccess)
	}
	return scopes
}

// dedup drops repeated scopes and keeps the first-seen order.
func dedup(scopes []string) []string {
	var kept []string
	for _, scope := range scopes {
		if !slices.Contains(kept, scope) {
			kept = append(kept, scope)
		}
	}
	return kept
}
