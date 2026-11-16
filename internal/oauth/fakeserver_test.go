package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// fakeServer is the MCP server, the authorization server and the registration
// endpoint in one, on a loopback address.
type fakeServer struct {
	t      *testing.T
	server *httptest.Server

	mu sync.Mutex
	// accessToken is the token the MCP endpoint accepts.
	accessToken string
	// refreshToken is the refresh token the token endpoint accepts.
	refreshToken string
	// refreshGrant is how the token endpoint answers a refresh: "" is a new
	// pair, "reuse" leaves out the refresh token, "invalid_grant" rejects.
	refreshGrant string
	// issuerOverride replaces the issuer of the metadata when set.
	issuerOverride string
	// registered holds the bodies of the registrations.
	registered []map[string]any
	// tokenRequests holds the forms of the token endpoint.
	tokenRequests []url.Values
	tokenAuth     []string
	// formTokens makes the token endpoint answer in form encoding.
	formTokens bool
	// authorizeSuffix is appended to the authorization endpoint.
	authorizeSuffix string
	// challenge is the code_challenge of the last authorization request.
	challenge string
	// bearers holds the Authorization headers the MCP endpoint saw.
	bearers []string
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fake := &fakeServer{t: t, accessToken: "access-1", refreshToken: "refresh-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", fake.mcp)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", fake.resourceMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server", fake.authorizationMetadata)
	mux.HandleFunc("/register", fake.register)
	mux.HandleFunc("/authorize", fake.authorize)
	mux.HandleFunc("/token", fake.token)
	fake.server = httptest.NewServer(mux)
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeServer) mcpURL() string { return f.server.URL + "/mcp" }

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (f *fakeServer) resourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{
		"resource":              f.mcpURL(),
		"authorization_servers": []string{f.server.URL},
		"scopes_supported":      []string{"read"},
	})
}

func (f *fakeServer) issuer() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issuerOverride != "" {
		return f.issuerOverride
	}
	return f.server.URL
}

func (f *fakeServer) authorizationMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{
		"issuer":                           f.issuer(),
		"authorization_endpoint":           f.server.URL + "/authorize" + f.authorizeSuffix,
		"token_endpoint":                   f.server.URL + "/token",
		"registration_endpoint":            f.server.URL + "/register",
		"response_types_supported":         []string{"code"},
		"code_challenge_methods_supported": []string{"S256"},
		"scopes_supported":                 []string{"read", "offline_access"},
	})
}

func (f *fakeServer) register(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	f.registered = append(f.registered, body)
	f.mu.Unlock()
	writeJSON(w, 201, map[string]any{"client_id": "dynamic-client", "redirect_uris": body["redirect_uris"]})
}

// authorize sends the browser back to the redirect URI at once.
func (f *fakeServer) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" || query.Get("resource") != f.mcpURL() {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.challenge = query.Get("code_challenge")
	f.mu.Unlock()
	back, _ := url.Parse(query.Get("redirect_uri"))
	values := back.Query()
	values.Set("code", "code-1")
	values.Set("state", query.Get("state"))
	back.RawQuery = values.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (f *fakeServer) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenRequests = append(f.tokenRequests, r.PostForm)
	f.tokenAuth = append(f.tokenAuth, r.Header.Get("Authorization"))
	if r.PostForm.Get("grant_type") == "authorization_code" {
		digest := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(digest[:]) != f.challenge || r.PostForm.Get("code") != "code-1" {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
			return
		}
		if f.formTokens {
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, _ = io.WriteString(w, "access_token="+f.accessToken+"&token_type=bearer&expires_in=3600&refresh_token="+f.refreshToken+"&scope=read&extra=1")
			return
		}
		writeJSON(w, 200, map[string]any{"access_token": f.accessToken, "token_type": "Bearer", "expires_in": 3600, "refresh_token": f.refreshToken, "scope": "read"})
		return
	}
	f.refreshAnswer(w, r.PostForm)
}

func (f *fakeServer) refreshAnswer(w http.ResponseWriter, form url.Values) {
	if f.refreshGrant == "echo" {
		http.Error(w, "cannot refresh "+form.Get("refresh_token"), http.StatusBadRequest)
		return
	}
	if f.refreshGrant == "invalid_grant" || form.Get("refresh_token") != f.refreshToken {
		writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
		return
	}
	f.accessToken = "access-2"
	answer := map[string]any{"access_token": "access-2", "token_type": "Bearer", "expires_in": 3600}
	if f.refreshGrant != "reuse" {
		f.refreshToken = "refresh-2"
		answer["refresh_token"] = "refresh-2"
	}
	writeJSON(w, 200, answer)
}

func (f *fakeServer) mcp(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.bearers = append(f.bearers, r.Header.Get("Authorization"))
	accepted := "Bearer " + f.accessToken
	f.mu.Unlock()
	if r.Header.Get("Authorization") != accepted {
		challenge := `Bearer resource_metadata="` + f.server.URL + `/.well-known/oauth-protected-resource/mcp"`
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var message struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	_ = json.Unmarshal(body, &message)
	switch {
	case message.Method == "initialize":
		writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]any{},
			"serverInfo":      map[string]any{"name": "fake", "version": "1"},
		}})
	case len(message.ID) == 0 || strings.HasPrefix(message.Method, "notifications/"):
		w.WriteHeader(http.StatusAccepted)
	default:
		writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": message.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
	}
}

func (f *fakeServer) lastBearer() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.bearers) == 0 {
		return ""
	}
	return f.bearers[len(f.bearers)-1]
}
