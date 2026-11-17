package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sort"

	"github.com/henry40408/toolward/internal/cache"
	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/names"
	"github.com/henry40408/toolward/internal/rawjson"
)

// toolMap says how the agent-facing names of one upstream's tools map back.
type toolMap struct {
	exposed   map[string]string
	originals map[string]bool
}

// ToolName is an agent-facing name (without the "<server>__" prefix) and the
// upstream's own name for the same tool.
type ToolName struct {
	Exposed  string
	Original string
}

// Tools lists the tools under the names the agent sees (without the
// "<server>__" prefix) and remembers how to map them back.
func (u *Upstream) Tools(ctx context.Context) (cache.Listed[json.RawMessage], error) {
	session, err := u.ListPeer(ctx)
	if err != nil {
		return cache.Listed[json.RawMessage]{}, err
	}
	return u.toolsFrom(ctx, session)
}

func (u *Upstream) toolsFrom(ctx context.Context, session *mcpwire.Session) (cache.Listed[json.RawMessage], error) {
	listed, err := Bounded(ctx, u, func(ctx context.Context) (cache.Listed[json.RawMessage], error) {
		return List(ctx, session, ListTools)
	})
	if err != nil {
		return cache.Listed[json.RawMessage]{}, err
	}
	originals := toolNames(listed.Items)
	assignment := names.Assign(u.name, originals)
	tools, mapped, renamed, err := u.rename(listed.Items, assignment)
	if err != nil {
		return cache.Listed[json.RawMessage]{}, err
	}
	if u.storeTools(mapped) {
		u.logRenames(renamed, assignment.Dropped)
	}
	return cache.Listed[json.RawMessage]{Items: tools, Hint: listed.Hint}, nil
}

func toolNames(tools []json.RawMessage) []string {
	originals := make([]string, 0, len(tools))
	for _, tool := range tools {
		if name, ok := rawjson.String(tool, "name"); ok {
			originals = append(originals, name)
		}
	}
	return originals
}

// rename gives the tools their exposed names. A tool the assignment dropped
// is left out, and when the upstream listed a name twice, the first one wins.
func (u *Upstream) rename(tools []json.RawMessage, assignment names.Assignment) ([]json.RawMessage, *toolMap, []ToolName, error) {
	exposedOf := map[string]string{}
	for _, pair := range assignment.Names {
		exposedOf[pair.Original] = pair.Exposed
	}
	mapped := &toolMap{exposed: map[string]string{}, originals: map[string]bool{}}
	var kept []json.RawMessage
	var renamed []ToolName
	for _, tool := range tools {
		original, named := rawjson.String(tool, "name")
		exposed, known := exposedOf[original]
		// A tool without a name cannot be called, so it is left out.
		if !named || !known || mapped.originals[original] {
			continue
		}
		if exposed != original {
			renamed = append(renamed, ToolName{Exposed: exposed, Original: original})
		}
		mapped.exposed[exposed] = original
		mapped.originals[original] = true
		renamedTool, err := rawjson.SetString(tool, "name", exposed)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid tool %q: %w", original, err)
		}
		kept = append(kept, renamedTool)
	}
	return kept, mapped, renamed, nil
}

// storeTools replaces the map and reports whether the exposed names changed.
func (u *Upstream) storeTools(mapped *toolMap) bool {
	u.toolsMu.Lock()
	defer u.toolsMu.Unlock()
	changed := u.tools == nil || !maps.Equal(u.tools.exposed, mapped.exposed)
	u.tools = mapped
	return changed
}

func (u *Upstream) logRenames(renamed []ToolName, dropped []string) {
	for _, tool := range renamed {
		Log(u.log, fmt.Sprintf("tool %q of %q is exposed as %q",
			tool.Original, u.name, u.name+names.Separator+tool.Exposed))
	}
	for _, original := range dropped {
		Log(u.log, fmt.Sprintf("tool %q of %q is dropped: its name collides with another tool", original, u.name))
	}
}

func (u *Upstream) forgetTools() {
	u.toolsMu.Lock()
	defer u.toolsMu.Unlock()
	u.tools = nil
}

// ToolNames returns the pairs of the last listing, sorted.
func (u *Upstream) ToolNames() []ToolName {
	u.toolsMu.Lock()
	defer u.toolsMu.Unlock()
	if u.tools == nil {
		return nil
	}
	pairs := make([]ToolName, 0, len(u.tools.exposed))
	for exposed, original := range u.tools.exposed {
		pairs = append(pairs, ToolName{Exposed: exposed, Original: original})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Exposed != pairs[j].Exposed {
			return pairs[i].Exposed < pairs[j].Exposed
		}
		return pairs[i].Original < pairs[j].Original
	})
	return pairs
}

// lookupTool finds the upstream's own name for a tool the agent called.
func (u *Upstream) lookupTool(called string) (string, bool) {
	u.toolsMu.Lock()
	defer u.toolsMu.Unlock()
	if u.tools == nil {
		return "", false
	}
	if original, ok := u.tools.exposed[called]; ok {
		return original, true
	}
	if u.tools.originals[called] {
		return called, true
	}
	return "", false
}

// OriginalTool is the upstream's own name for a tool the agent called. It
// accepts the exposed name and the original one, and lists the tools again
// once when the name is unknown. It reports false for a tool that does not
// exist.
func (u *Upstream) OriginalTool(ctx context.Context, called string) (string, bool, error) {
	if original, ok := u.lookupTool(called); ok {
		return original, true, nil
	}
	// A tool call may wait for a slow start as long as any other call; only a
	// plain listing gives up early.
	session, err := u.Peer(ctx)
	if err != nil {
		return "", false, err
	}
	if _, err := u.toolsFrom(ctx, session); err != nil {
		return "", false, err
	}
	original, ok := u.lookupTool(called)
	return original, ok, nil
}
