package cache

import (
	"context"
	"encoding/json"
)

// Listed is a complete listing and the hint it may be cached with.
type Listed[T any] struct {
	Items []T
	Hint  Hint
}

// Page is one page of a listing. An empty NextCursor ends the listing.
type Page[T any] struct {
	Items      []T
	NextCursor string
	Hint       Hint
}

// NextCursorOf reads "nextCursor" of a raw list result.
func NextCursorOf(result json.RawMessage) string {
	var fields struct {
		NextCursor string `json:"nextCursor"`
	}
	if err := json.Unmarshal(result, &fields); err != nil {
		return ""
	}
	return fields.NextCursor
}

// CollectPages follows the next cursor to the end. fetch gets an empty cursor
// for the first page. The hint is the weakest of all pages.
func CollectPages[T any](ctx context.Context, fetch func(ctx context.Context, cursor string) (Page[T], error)) (Listed[T], error) {
	var items []T
	var hints []Hint
	cursor := ""
	for {
		page, err := fetch(ctx, cursor)
		if err != nil {
			return Listed[T]{}, err
		}
		items = append(items, page.Items...)
		hints = append(hints, page.Hint)
		cursor = page.NextCursor
		if cursor == "" {
			return Listed[T]{Items: items, Hint: WeakestOf(hints)}, nil
		}
		if err := ctx.Err(); err != nil {
			return Listed[T]{}, err
		}
	}
}
