package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/henry40408/toolward/internal/cache"
	"github.com/henry40408/toolward/internal/mcpwire"
	"github.com/henry40408/toolward/internal/rawjson"
)

// resourceScheme starts every exposed resource. They look like
// toolward://<server>/<percent-encoded upstream URI>.
const resourceScheme = "toolward://"

const hexDigits = "0123456789ABCDEF"

// encodeURI percent-encodes everything but unreserved characters.
func encodeURI(uri string) string {
	var out strings.Builder
	for i := range len(uri) {
		b := uri[i]
		if isUnreserved(b) {
			out.WriteByte(b)
			continue
		}
		out.WriteByte('%')
		out.WriteByte(hexDigits[b>>4])
		out.WriteByte(hexDigits[b&0x0f])
	}
	return out.String()
}

func isUnreserved(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		b == '-' || b == '.' || b == '_' || b == '~'
}

func decodeURI(text string) (string, bool) {
	out := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		if text[i] != '%' {
			out = append(out, text[i])
			continue
		}
		if i+2 >= len(text) {
			return "", false
		}
		high, okHigh := hexValue(text[i+1])
		low, okLow := hexValue(text[i+2])
		if !okHigh || !okLow {
			return "", false
		}
		out = append(out, high<<4|low)
		i += 2
	}
	if !utf8.Valid(out) {
		return "", false
	}
	return string(out), true
}

func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// exposeURI gives the URI the agent sees for an upstream URI.
func exposeURI(server, uri string) string {
	return resourceScheme + server + "/" + encodeURI(uri)
}

// restoreURI splits an exposed URI into the server and the upstream's own URI.
func restoreURI(uri string) (server, original string, ok bool) {
	rest, found := strings.CutPrefix(uri, resourceScheme)
	if !found {
		return "", "", false
	}
	server, encoded, found := strings.Cut(rest, "/")
	if !found {
		return "", "", false
	}
	original, ok = decodeURI(encoded)
	return server, original, ok
}

type readParams struct {
	URI string `json:"uri"`
}

func (p *Proxy) readResource(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	var request readParams
	if err := json.Unmarshal(params, &request); err != nil {
		return nil, mcpwire.InvalidParams(fmt.Sprintf("invalid params: %v", err))
	}
	server, original, ok := restoreURI(request.URI)
	if !ok {
		return nil, mcpwire.InvalidParams("unknown resource")
	}
	u := p.upstreams[server]
	if u == nil {
		return nil, mcpwire.InvalidParams("unknown resource")
	}
	session, err := u.Peer(ctx)
	if err != nil {
		return nil, unavailable(server, err)
	}
	renamed, err := rawjson.SetString(params, "uri", original)
	if err != nil {
		return nil, mcpwire.InternalError(err.Error())
	}
	result, err := forward(ctx, u, session, "resources/read", renamed)
	if err != nil {
		return nil, err
	}
	return exposedRead(server, result)
}

// exposedRead completes a read result. The upstream's hints pass through as
// they are, but a server older than 2026-07-28 gave none and the agent needs
// them.
func exposedRead(server string, result json.RawMessage) (json.RawMessage, error) {
	result, err := withResultType(result)
	if err != nil {
		return nil, mcpwire.InternalError(err.Error())
	}
	hint := cache.HintOf(result)
	if result, err = rawjson.SetRaw(result, "ttlMs", json.RawMessage(fmt.Sprint(hint.TTLMs))); err != nil {
		return nil, mcpwire.InternalError(err.Error())
	}
	if result, err = rawjson.SetString(result, "cacheScope", string(hint.Scope)); err != nil {
		return nil, mcpwire.InternalError(err.Error())
	}
	result, err = exposeContents(server, result)
	if err != nil {
		return nil, mcpwire.InternalError(err.Error())
	}
	return result, nil
}

func exposeContents(server string, result json.RawMessage) (json.RawMessage, error) {
	raw := rawjson.Raw(result, "contents")
	if raw == nil {
		return result, nil
	}
	var contents []json.RawMessage
	if err := json.Unmarshal(raw, &contents); err != nil {
		return nil, fmt.Errorf("invalid contents: %w", err)
	}
	for i, content := range contents {
		uri, ok := rawjson.String(content, "uri")
		if !ok {
			continue
		}
		renamed, err := rawjson.SetString(content, "uri", exposeURI(server, uri))
		if err != nil {
			return nil, err
		}
		contents[i] = renamed
	}
	encoded, err := rawjson.Marshal(contents)
	if err != nil {
		return nil, err
	}
	return rawjson.SetRaw(result, "contents", encoded)
}
