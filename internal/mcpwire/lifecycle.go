package mcpwire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// Implementation names a client or a server.
type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitInfo is what the server told about itself while the connection opened.
type InitInfo struct {
	ProtocolVersion string
	ServerInfo      Implementation
	Capabilities    json.RawMessage
}

// Session is a connected client. Over the stateless protocol it adds the
// inline lifecycle keys to every request.
type Session struct {
	Peer *Peer
	Info InitInfo

	inlineMeta map[string]json.RawMessage
}

// Call sends a request.
func (s *Session) Call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	if s.inlineMeta == nil {
		return s.Peer.Call(ctx, method, params)
	}
	withMeta, err := withMeta(params, s.inlineMeta)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return s.Peer.Call(ctx, method, withMeta)
}

// Initialize opens the connection with the initialize handshake, offering
// 2025-11-25. That version is not a choice of the server: the default of newer
// clients, 2026-07-28, has no handshake, and some servers answer initialize
// but then refuse the follow-up.
func Initialize(ctx context.Context, peer *Peer, client Implementation) (*Session, error) {
	params, err := json.Marshal(map[string]any{
		"protocolVersion": Version20251125,
		"capabilities":    json.RawMessage(emptyObject),
		"clientInfo":      client,
	})
	if err != nil {
		return nil, err
	}
	raw, err := peer.Call(ctx, methodInitialize, params)
	if err != nil {
		return nil, wrapJSONRPCError(err)
	}
	info, err := decodeInitializeResult(raw)
	if err != nil {
		return nil, err
	}
	session := &Session{Peer: peer, Info: info}
	if !hasInitialize(info.ProtocolVersion) {
		session.inlineMeta, err = inlineMeta(info.ProtocolVersion, client)
		if err != nil {
			return nil, err
		}
	}
	if err := peer.Notify(methodInitialized, nil); err != nil {
		return nil, err
	}
	return session, nil
}

func wrapJSONRPCError(err error) error {
	var rpcErr *Error
	if errors.As(err, &rpcErr) {
		return fmt.Errorf("JSON-RPC error: %w", err)
	}
	return err
}

func decodeInitializeResult(raw json.RawMessage) (InitInfo, error) {
	var result struct {
		ProtocolVersion string          `json:"protocolVersion"`
		Capabilities    json.RawMessage `json:"capabilities"`
		ServerInfo      Implementation  `json:"serverInfo"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.ProtocolVersion == "" {
		return InitInfo{}, fmt.Errorf("expect initialized result, but received: %s", raw)
	}
	return InitInfo{
		ProtocolVersion: result.ProtocolVersion,
		ServerInfo:      result.ServerInfo,
		Capabilities:    result.Capabilities,
	}, nil
}

func inlineMeta(version string, client Implementation) (map[string]json.RawMessage, error) {
	versionJSON, err := json.Marshal(version)
	if err != nil {
		return nil, err
	}
	clientJSON, err := json.Marshal(client)
	if err != nil {
		return nil, err
	}
	return map[string]json.RawMessage{
		MetaProtocolVersion:    versionJSON,
		MetaClientInfo:         clientJSON,
		MetaClientCapabilities: json.RawMessage(emptyObject),
	}, nil
}

// Discover opens the connection without a handshake: server/discover asks for
// the server's versions and capabilities, and every later request carries the
// lifecycle keys in its "_meta".
//
// The caller decides what a failure means. A JSON-RPC error that is not about
// versions or capabilities says the server is older and needs Initialize.
func Discover(ctx context.Context, peer *Peer, client Implementation) (*Session, error) {
	preferred := []string{Version20260728}
	attempt := discoverAttempt{peer: peer, client: client, preferred: preferred}
	attempted := []string{}
	candidate := preferred[0]
	for {
		attempted = append(attempted, candidate)
		session, err := attempt.run(ctx, candidate)
		if err == nil {
			return session, nil
		}
		next, retry := nextCandidate(err, preferred, attempted, candidate)
		if !retry {
			return nil, err
		}
		candidate = next
	}
}

// discoverAttempt holds what stays the same between the tries of Discover.
type discoverAttempt struct {
	peer      *Peer
	client    Implementation
	preferred []string
}

func (a discoverAttempt) run(ctx context.Context, candidate string) (*Session, error) {
	meta, err := inlineMeta(candidate, a.client)
	if err != nil {
		return nil, err
	}
	params, err := withMeta(nil, meta)
	if err != nil {
		return nil, err
	}
	raw, err := a.peer.Call(ctx, methodDiscover, params)
	if err != nil {
		return nil, wrapJSONRPCError(err)
	}
	return sessionFromDiscover(a, raw)
}

func sessionFromDiscover(a discoverAttempt, raw json.RawMessage) (*Session, error) {
	var result struct {
		SupportedVersions []string        `json:"supportedVersions"`
		Capabilities      json.RawMessage `json:"capabilities"`
		Meta              struct {
			ServerInfo Implementation `json:"io.modelcontextprotocol/serverInfo"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.SupportedVersions == nil {
		return nil, fmt.Errorf("expect initialized result, but received: %s", raw)
	}
	selected, ok := firstShared(a.preferred, result.SupportedVersions)
	if !ok {
		return nil, fmt.Errorf("no compatible protocol version (client: %q, server: %q)", a.preferred, result.SupportedVersions)
	}
	meta, err := inlineMeta(selected, a.client)
	if err != nil {
		return nil, err
	}
	return &Session{
		Peer: a.peer,
		Info: InitInfo{
			ProtocolVersion: selected,
			ServerInfo:      result.Meta.ServerInfo,
			Capabilities:    result.Capabilities,
		},
		inlineMeta: meta,
	}, nil
}

func firstShared(preferred, supported []string) (string, bool) {
	for _, version := range preferred {
		if slices.Contains(supported, version) {
			return version, true
		}
	}
	return "", false
}

// nextCandidate decides whether a server's "unsupported protocol version"
// answer lets discovery try again, and with which version. Like rmcp, it tries
// the current version a second time and no other one more than once.
func nextCandidate(err error, preferred, attempted []string, candidate string) (string, bool) {
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != CodeUnsupportedProtocolVersion {
		return "", false
	}
	var data struct {
		Supported []string `json:"supported"`
	}
	_ = json.Unmarshal(rpcErr.Data, &data)
	mayRetryCurrent := count(attempted, candidate) == 1
	for _, version := range preferred {
		if !slices.Contains(data.Supported, version) {
			continue
		}
		if !slices.Contains(attempted, version) || (mayRetryCurrent && version == candidate) {
			return version, true
		}
	}
	return "", false
}

func count(list []string, want string) int {
	total := 0
	for _, item := range list {
		if item == want {
			total++
		}
	}
	return total
}

// IsModernRejection says whether a failed discover came from a server that
// speaks the stateless protocol and refused this client, instead of one that
// does not know server/discover.
func IsModernRejection(err error) bool {
	var rpcErr *Error
	if !errors.As(err, &rpcErr) {
		return false
	}
	return rpcErr.Code == CodeMissingRequiredClientCapability ||
		rpcErr.Code == CodeHeaderMismatch ||
		rpcErr.Code == CodeUnsupportedProtocolVersion
}
