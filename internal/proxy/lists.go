package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/henry40408/toolward/internal/cache"
	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/names"
	"github.com/henry40408/toolward/internal/rawjson"
	"github.com/henry40408/toolward/internal/upstream"
)

// listing describes one kind of merged listing.
type listing struct {
	kind upstream.ListKind
	// capability is the key of the upstream's capabilities that must be
	// present for the upstream to have anything to list.
	capability string
	// identifier is the field of an item that the proxy rewrites.
	identifier string
	// expose gives the identifier the agent sees.
	expose func(server, original string) string
}

var (
	toolsListing = listing{
		kind: upstream.ListTools, capability: "tools", identifier: "name",
		expose: exposeName,
	}
	resourcesListing = listing{
		kind: upstream.ListResources, capability: "resources", identifier: "uri",
		expose: exposeURI,
	}
	promptsListing = listing{
		kind: upstream.ListPrompts, capability: "prompts", identifier: "name",
		expose: exposeName,
	}
)

func exposeName(server, original string) string {
	return server + names.Separator + original
}

// fetched is what one upstream contributed to a listing.
type fetched struct {
	items []json.RawMessage
	hint  cache.Hint
	// skipped is true when the upstream has nothing to list.
	skipped bool
	err     error
}

func (p *Proxy) listTools(ctx context.Context) (json.RawMessage, error) {
	return p.merge(ctx, toolsListing)
}

func (p *Proxy) listResources(ctx context.Context) (json.RawMessage, error) {
	return p.merge(ctx, resourcesListing)
}

func (p *Proxy) listPrompts(ctx context.Context) (json.RawMessage, error) {
	return p.merge(ctx, promptsListing)
}

// listResourceTemplates answers with the empty list: templates are not
// exposed, so the list is complete and never changes.
func (p *Proxy) listResourceTemplates() (json.RawMessage, error) {
	return listResult("resourceTemplates", nil, cache.Uncacheable)
}

// merge lists every upstream at once and combines the answers. An unavailable
// upstream is skipped, not fatal. The list is then incomplete, so the agent
// must not keep it.
func (p *Proxy) merge(ctx context.Context, spec listing) (json.RawMessage, error) {
	results := make([]fetched, len(p.names))
	done := make(chan struct{}, len(p.names))
	for i, name := range p.names {
		go func() {
			defer func() { done <- struct{}{} }()
			results[i] = p.fetchFrom(ctx, p.upstreams[name], spec)
		}()
	}
	for range p.names {
		<-done
	}
	return p.combine(spec, results)
}

func (p *Proxy) combine(spec listing, results []fetched) (json.RawMessage, error) {
	type entry struct {
		key  string
		item json.RawMessage
	}
	var entries []entry
	var hints []cache.Hint
	for i, result := range results {
		name := p.names[i]
		switch {
		case result.err != nil:
			hints = append(hints, cache.Uncacheable)
			upstream.Log(p.log, fmt.Sprintf("skipping upstream %q: %v", name, result.err))
		case result.skipped:
		default:
			hints = append(hints, result.hint)
			for _, item := range result.items {
				exposed, key, err := expose(spec, name, item)
				if err != nil {
					hints = append(hints, cache.Uncacheable)
					upstream.Log(p.log, fmt.Sprintf("skipping an item of upstream %q: %v", name, err))
					continue
				}
				entries = append(entries, entry{key: key, item: exposed})
			}
		}
	}
	sort.SliceStable(entries, func(a, b int) bool { return entries[a].key < entries[b].key })
	items := make([]json.RawMessage, 0, len(entries))
	for _, e := range entries {
		items = append(items, e.item)
	}
	return listResult(spec.kind.Field, items, cache.WeakestOf(hints))
}

// expose rewrites the identifier of an item and returns it with its sort key.
func expose(spec listing, server string, item json.RawMessage) (json.RawMessage, string, error) {
	original, ok := rawjson.String(item, spec.identifier)
	if !ok {
		return nil, "", fmt.Errorf("no %q", spec.identifier)
	}
	exposed := spec.expose(server, original)
	renamed, err := rawjson.SetString(item, spec.identifier, exposed)
	if err != nil {
		return nil, "", err
	}
	return renamed, exposed, nil
}

func listResult(field string, items []json.RawMessage, hint cache.Hint) (json.RawMessage, error) {
	if items == nil {
		items = []json.RawMessage{}
	}
	return rawjson.Marshal(map[string]any{
		field:        items,
		"ttlMs":      hint.TTLMs,
		"cacheScope": hint.Scope,
	})
}

// fetchFrom lists one upstream. A panic only costs this upstream's items.
func (p *Proxy) fetchFrom(ctx context.Context, u *upstream.Upstream, spec listing) (result fetched) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = fetched{err: fmt.Errorf("listing panicked: %v", recovered)}
		}
	}()
	session, err := u.ListPeer(ctx)
	if err != nil {
		return fetched{err: err}
	}
	if !supports(session, spec.capability) {
		return fetched{skipped: true}
	}
	listed, err := p.list(ctx, u, session, spec)
	if err != nil {
		return fetched{err: err}
	}
	return fetched{items: listed.Items, hint: listed.Hint}
}

func (p *Proxy) list(ctx context.Context, u *upstream.Upstream, session *mcpwire.Session, spec listing) (cache.Listed[json.RawMessage], error) {
	var listed cache.Listed[json.RawMessage]
	var err error
	if spec.kind == upstream.ListTools {
		listed, err = u.Tools(ctx)
	} else {
		listed, err = upstream.Bounded(ctx, u, func(ctx context.Context) (cache.Listed[json.RawMessage], error) {
			return upstream.List(ctx, session, spec.kind)
		})
	}
	if err != nil {
		return cache.Listed[json.RawMessage]{}, err
	}
	return u.RedactListed(listed)
}

// supports reports whether the upstream announced the capability. Unknown
// counts as yes.
func supports(session *mcpwire.Session, capability string) bool {
	if len(session.Info.Capabilities) == 0 {
		return true
	}
	var announced map[string]json.RawMessage
	if json.Unmarshal(session.Info.Capabilities, &announced) != nil {
		return true
	}
	value, ok := announced[capability]
	return ok && string(value) != "null"
}
