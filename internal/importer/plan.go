// Package importer moves the plaintext secrets of an existing `mcp.json` into
// the credential store and produces the matching toolward config.
//
// Only environment variables and HTTP headers whose names look like secrets
// are moved. Nothing here prints or logs a secret value.
package importer

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/henry40408/toolward/internal/config"
)

// Move is one value that moves into the credential store.
type Move struct {
	Server string
	// Place is for example `env GITHUB_TOKEN` or `header Authorization`.
	Place   string
	Account string
}

// Plan is what an import would do. It holds secret values, so it never prints
// them.
type Plan struct {
	// servers are the `mcpServers` entries, with references where secrets were.
	servers object
	Moves   []Move
	secrets []plannedSecret
	// Skipped are the servers left out, with the reason.
	Skipped []string
	// Notes are things the user should look at by hand.
	Notes []string
}

// String keeps the secrets out of `%v` and `%+v`. It has a value receiver so
// that formatting a Plan value is covered too, not only a *Plan.
func (p Plan) String() string {
	return fmt.Sprintf("import plan (%d moves, %d skipped)", len(p.Moves), len(p.Skipped))
}

// GoString keeps the secrets out of `%#v`.
func (p Plan) GoString() string {
	return p.String()
}

// ConfigJSON returns the toolward config that results, on one line and
// without any secret.
func (p *Plan) ConfigJSON() string {
	return encodeCompact(object{"mcpServers": p.servers})
}

// NewPlan reads a Claude-style `mcp.json` and plans the move.
func NewPlan(source string) (*Plan, error) {
	root, err := parseDocument(source)
	if err != nil {
		return nil, errors.New("the file is not valid JSON")
	}
	document, _ := root.(object)
	servers, ok := document["mcpServers"].(object)
	if !ok {
		return nil, errors.New(`the file has no "mcpServers" object`)
	}
	plan := planServers(servers)
	// The result must be a config toolward accepts, or nothing is stored.
	if _, err := config.Parse(plan.ConfigJSON()); err != nil {
		return nil, fmt.Errorf("the imported servers are not valid: %s", safeError(err))
	}
	return plan, nil
}

func planServers(servers object) *Plan {
	planner := &planner{used: map[string]bool{}}
	plan := &Plan{servers: object{}}
	for _, name := range slices.Sorted(maps.Keys(servers)) {
		planned, reason := planner.planServer(name, servers[name])
		if reason != "" {
			plan.Skipped = append(plan.Skipped, name+": "+reason)
			continue
		}
		plan.servers[name] = planned
	}
	plan.Moves = planner.moves
	plan.secrets = planner.secrets
	plan.Notes = planner.notes
	return plan
}

// planServer plans one server. A reason means the server is left out.
func (p *planner) planServer(name string, raw any) (server object, reason string) {
	server, ok := raw.(object)
	if !ok {
		return nil, "not an object"
	}
	if kind, _ := server["type"].(string); kind == "sse" {
		return nil, "SSE servers are not supported"
	}
	if _, has := server["oauth"]; has {
		return nil, `already has an "oauth" setting`
	}
	if reason := inlineSecret(server); reason != "" {
		return nil, reason + "; move it into env by hand, then import again"
	}
	before := p.mark()
	if env, ok := server["env"].(object); ok {
		p.extractSecrets(name, "env", env)
	}
	if headers, ok := server["headers"].(object); ok {
		p.extractSecrets(name, "header", headers)
	}
	// A server toolward cannot load (for example one with a foreign ${...}
	// reference) is left out whole, and its moves are undone.
	if _, err := config.Parse(encodeCompact(object{"mcpServers": object{name: server}})); err != nil {
		p.rollBackTo(before)
		return nil, safeError(err)
	}
	return server, ""
}
