package mcpwire

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// MethodHandler answers the methods that carry the server's actual content:
// tools/list, tools/call, resources/list, resources/templates/list,
// resources/read, prompts/list and prompts/get.
type MethodHandler interface {
	HandleRequest(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error)
}

// ServerConfig describes the server a Server presents to its client.
type ServerConfig struct {
	Info         Implementation
	Capabilities json.RawMessage
	Instructions string
	Methods      MethodHandler
	// OnInitialized runs when a client that used the initialize handshake
	// says it is ready. The peer reaches the client.
	OnInitialized func(peer *Peer)
}

type sessionState int

const (
	// No lifecycle yet: ping and server/discover are answered, and the first
	// initialize or the first request with inline meta picks the lifecycle.
	statePending sessionState = iota
	stateHandshake
	stateInline
)

var contentMethods = map[string]bool{
	"tools/list":               true,
	"tools/call":               true,
	"resources/list":           true,
	"resources/templates/list": true,
	"resources/read":           true,
	"prompts/list":             true,
	"prompts/get":              true,
}

// Server is the downstream side of one connection. It is the Handler of the
// peer that serves the client. It follows rmcp: initialize, server/discover
// and requests with inline meta all work, and the first of initialize or an
// inline request decides how the rest of the connection goes.
type Server struct {
	config ServerConfig

	mu    sync.Mutex
	state sessionState
}

// NewServer returns the handler of a connection.
func NewServer(config ServerConfig) *Server {
	return &Server{config: config}
}

// HandleRequest answers one request of the client.
func (s *Server) HandleRequest(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	meta := requestMeta(params)
	if s.currentState() == statePending {
		return s.handlePending(ctx, method, params, meta)
	}
	return s.handleSession(ctx, method, params, meta)
}

func (s *Server) currentState() sessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// enter moves a pending connection into a lifecycle. Later calls change nothing.
func (s *Server) enter(state sessionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == statePending {
		s.state = state
	}
}

func (s *Server) handlePending(ctx context.Context, method string, params json.RawMessage, meta map[string]json.RawMessage) (json.RawMessage, error) {
	switch method {
	case methodPing:
		return json.RawMessage(emptyObject), nil
	case methodInitialize:
		return s.initialize(params)
	}
	if err := checkInlineRequest(meta); err != nil {
		return nil, err
	}
	if method == methodDiscover {
		return s.discover(), nil
	}
	s.enter(stateInline)
	return s.handleSession(ctx, method, params, meta)
}

// checkInlineRequest holds a request that carries its own lifecycle to the
// rules of 2026-07-28: the required keys, and a version this server speaks.
func checkInlineRequest(meta map[string]json.RawMessage) error {
	if missing := missingMetaKeys(meta); len(missing) > 0 {
		return missingMetaError(missing)
	}
	version, _ := metaVersion(meta)
	return checkVersion(version)
}

func missingMetaError(missing []string) *Error {
	return InvalidParams("request _meta is missing or has malformed required fields: " + strings.Join(missing, ", "))
}

func checkVersion(version string) error {
	if isKnownVersion(version) {
		return nil
	}
	data, err := json.Marshal(map[string]any{"requested": version, "supported": KnownVersions})
	if err != nil {
		return InternalError(err.Error())
	}
	return &Error{Code: CodeUnsupportedProtocolVersion, Message: "Unsupported protocol version", Data: data}
}

func (s *Server) handleSession(ctx context.Context, method string, params json.RawMessage, meta map[string]json.RawMessage) (json.RawMessage, error) {
	if method == methodInitialize {
		return s.initialize(params)
	}
	inline, err := s.requiresInlineMeta(method, meta)
	if err != nil {
		return nil, err
	}
	return s.dispatch(ctx, method, params, inline)
}

// requiresInlineMeta checks a request of an established connection. A request
// must carry the inline keys when the connection opened that way, when it is
// server/discover, or when it names 2026-07-28 or later itself.
func (s *Server) requiresInlineMeta(method string, meta map[string]json.RawMessage) (bool, error) {
	version, hasVersion := metaVersion(meta)
	if hasVersion {
		if err := checkVersion(version); err != nil {
			return false, err
		}
	}
	inline := s.currentState() == stateInline ||
		method == methodDiscover ||
		(hasVersion && !hasInitialize(version))
	if !inline {
		return false, nil
	}
	if missing := missingMetaKeys(meta); len(missing) > 0 {
		return false, missingMetaError(missing)
	}
	return true, nil
}

func (s *Server) dispatch(ctx context.Context, method string, params json.RawMessage, inline bool) (json.RawMessage, error) {
	switch {
	case method == methodPing && !inline:
		return json.RawMessage(emptyObject), nil
	case method == methodDiscover:
		return s.discover(), nil
	case method == "completion/complete":
		return json.RawMessage(`{"completion":{"values":[]}}`), nil
	case contentMethods[method]:
		return s.config.Methods.HandleRequest(ctx, method, params)
	}
	return nil, MethodNotFound(method)
}

func (s *Server) initialize(params json.RawMessage) (json.RawMessage, error) {
	var request struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(params, &request); err != nil || request.ProtocolVersion == "" {
		return nil, InvalidParams("invalid initialize params")
	}
	s.enter(stateHandshake)
	result := struct {
		ProtocolVersion string          `json:"protocolVersion"`
		Capabilities    json.RawMessage `json:"capabilities"`
		ServerInfo      Implementation  `json:"serverInfo"`
		Instructions    string          `json:"instructions,omitempty"`
	}{negotiateVersion(request.ProtocolVersion), s.config.Capabilities, s.config.Info, s.config.Instructions}
	return marshalResult(result)
}

// negotiateVersion echoes the client's version when it still has a handshake
// and is known. Otherwise it answers with the newest version that has one.
func negotiateVersion(requested string) string {
	if hasInitialize(requested) && isKnownVersion(requested) {
		return requested
	}
	return Version20251125
}

func (s *Server) discover() json.RawMessage {
	result := struct {
		ResultType        string          `json:"resultType"`
		SupportedVersions []string        `json:"supportedVersions"`
		Capabilities      json.RawMessage `json:"capabilities"`
		Instructions      string          `json:"instructions,omitempty"`
		TTLMs             int             `json:"ttlMs"`
		CacheScope        string          `json:"cacheScope"`
		Meta              map[string]any  `json:"_meta"`
	}{
		ResultType:        "complete",
		SupportedVersions: KnownVersions,
		Capabilities:      s.config.Capabilities,
		Instructions:      s.config.Instructions,
		CacheScope:        "private",
		Meta:              map[string]any{MetaServerInfo: s.config.Info},
	}
	raw, _ := marshalResult(result)
	return raw
}

func marshalResult(result any) (json.RawMessage, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, InternalError(fmt.Sprintf("cannot encode the result: %v", err))
	}
	return raw, nil
}

// HandleNotification starts the work that waits for a ready client.
func (s *Server) HandleNotification(ctx context.Context, method string, _ json.RawMessage) {
	if method != methodInitialized || s.currentState() != stateHandshake {
		return
	}
	if s.config.OnInitialized != nil {
		s.config.OnInitialized(PeerFromContext(ctx))
	}
}
