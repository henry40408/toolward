package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/version"
)

const (
	methodToolsChanged     = "notifications/tools/list_changed"
	methodResourcesChanged = "notifications/resources/list_changed"
	methodPromptsChanged   = "notifications/prompts/list_changed"
)

// Log prints a diagnostic. Stdout belongs to the MCP protocol, so w is stderr
// in the real program. A nil w discards the line.
func Log(w io.Writer, message string) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, "toolward: %s\n", message)
}

// ClientInfo is what toolward calls itself when it connects to an upstream.
func ClientInfo() mcpwire.Implementation {
	return mcpwire.Implementation{Name: "toolward", Version: version.Version()}
}

// Hub is the connection to the agent, shared by every upstream so that a
// change on an upstream can be passed on.
type Hub struct {
	mu         sync.Mutex
	downstream *mcpwire.Peer
}

// SetDownstream remembers the agent's connection.
func (h *Hub) SetDownstream(peer *mcpwire.Peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.downstream = peer
}

// Downstream is nil until the agent has said it is ready.
func (h *Hub) Downstream() *mcpwire.Peer {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.downstream
}

func (h *Hub) forward(method string) {
	if peer := h.Downstream(); peer != nil {
		_ = peer.Notify(method, nil)
	}
}

// Handler receives what one upstream sends on its own and keeps the secrets
// used to connect to it. Connectors pass it to mcpwire.NewPeer.
type Handler struct {
	// The embedded handler answers roots/list and elicitation/create with
	// "method not found". toolward declares neither capability, so only an
	// upstream that breaks the rules sends them.
	mcpwire.ClientHandler
	hub         *Hub
	forgetTools func()

	mu      sync.Mutex
	secrets []string
}

// RememberSecrets is for connectors: it records the secrets they used, so
// that later errors, which the server may have filled with echoed headers,
// can be masked.
func (h *Handler) RememberSecrets(secrets []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.secrets = slices.Clone(secrets)
}

// AddSecrets adds secrets that appeared after the connection was made, such
// as a token the connector refreshed.
func (h *Handler) AddSecrets(secrets []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, secret := range secrets {
		if !slices.Contains(h.secrets, secret) {
			h.secrets = append(h.secrets, secret)
		}
	}
}

// Secrets returns a copy of the secrets to mask.
func (h *Handler) Secrets() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.secrets)
}

// HandleNotification passes list changes on to the agent.
func (h *Handler) HandleNotification(_ context.Context, method string, _ json.RawMessage) {
	switch method {
	case methodToolsChanged:
		h.forgetTools()
		h.hub.forward(method)
	case methodResourcesChanged, methodPromptsChanged:
		h.hub.forward(method)
	}
}
