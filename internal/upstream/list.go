package upstream

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/henry40408/toolward/internal/cache"
	"github.com/henry40408/toolward/internal/mcpwire"
)

// ListKind names a listing: the request and the field of its result that
// holds the items.
type ListKind struct {
	Method string
	Field  string
}

// The listings the proxy merges.
var (
	ListTools     = ListKind{Method: "tools/list", Field: "tools"}
	ListResources = ListKind{Method: "resources/list", Field: "resources"}
	ListPrompts   = ListKind{Method: "prompts/list", Field: "prompts"}
)

// List follows the cursor to the end and returns every item as the upstream
// sent it, with the weakest cache hint of all pages.
func List(ctx context.Context, session *mcpwire.Session, kind ListKind) (cache.Listed[json.RawMessage], error) {
	return cache.CollectPages(ctx, func(ctx context.Context, cursor string) (cache.Page[json.RawMessage], error) {
		return listPage(ctx, session, kind, cursor)
	})
}

func listPage(ctx context.Context, session *mcpwire.Session, kind ListKind, cursor string) (cache.Page[json.RawMessage], error) {
	params := json.RawMessage(`{}`)
	if cursor != "" {
		encoded, err := json.Marshal(map[string]string{"cursor": cursor})
		if err != nil {
			return cache.Page[json.RawMessage]{}, err
		}
		params = encoded
	}
	result, err := session.Call(ctx, kind.Method, params)
	if err != nil {
		return cache.Page[json.RawMessage]{}, err
	}
	items, err := itemsOf(result, kind.Field)
	if err != nil {
		return cache.Page[json.RawMessage]{}, err
	}
	return cache.Page[json.RawMessage]{
		Items:      items,
		NextCursor: cache.NextCursorOf(result),
		Hint:       cache.HintOf(result),
	}, nil
}

func itemsOf(result json.RawMessage, field string) ([]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(result, &fields); err != nil {
		return nil, fmt.Errorf("invalid list result: %w", err)
	}
	raw, ok := fields[field]
	if !ok {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("invalid %q in the list result: %w", field, err)
	}
	return items, nil
}
