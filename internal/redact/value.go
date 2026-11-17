package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

// ErrCannotInspect means a result could not be decoded, so it is not passed on
// unchecked.
var ErrCannotInspect = errors.New("cannot inspect the upstream result for secrets")

// protocolKeys are keys of the MCP protocol itself. Inside a protocol position
// their names are never masked, so a secret that is an ordinary word cannot
// rename a field.
var protocolKeys = []string{
	"type", "text", "data", "blob", "mimeType", "uri", "name", "title",
	"description", "role", "content", "contents", "resource", "annotations",
	"audience", "icons", "theme", "_meta", "structuredContent", "isError",
	"resultType", "inputSchema", "outputSchema", "arguments", "messages",
	"tools", "resources", "prompts", "nextCursor", "code", "message",
}

// protocolDescend are the keys through which the result stays a protocol
// position. Anything else (structuredContent, _meta, error data, schemas, call
// arguments) holds free-form data written by the upstream, and is masked
// without exceptions.
var protocolDescend = []string{
	"tools", "resources", "prompts", "content", "contents", "messages",
	"resource", "annotations", "icons",
}

// maxProtocolWordLen is the longest protocol word or identifier.
const maxProtocolWordLen = 128

// Value masks secrets in every string of the JSON value raw (text, structured
// content, resource and prompt bodies). A value that cannot be inspected is an
// error, never passed on unchecked. A value without a secret comes back as it
// was, with its key order.
func Value(raw json.RawMessage, secrets []string) (json.RawMessage, error) {
	patterns := resultPatterns(secrets)
	if len(patterns) == 0 {
		return raw, nil
	}
	if checkNoDuplicateKeys(raw) != nil {
		return nil, ErrCannotInspect
	}
	value, err := decodeUsingNumbers(raw)
	if err != nil {
		return nil, ErrCannotInspect
	}
	masked, changed := maskStrings(value, patterns, true)
	if !changed {
		return raw, nil
	}
	encoded, err := encodeWithoutHTMLEscaping(masked)
	if err != nil {
		return nil, ErrCannotInspect
	}
	return encoded, nil
}

func decodeUsingNumbers(raw json.RawMessage) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, errors.New("trailing data")
	}
	return value, nil
}

// encodeWithoutHTMLEscaping writes compact JSON with sorted object keys.
func encodeWithoutHTMLEscaping(value any) (json.RawMessage, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// maskStrings masks the patterns in every string of value and reports whether
// anything changed. protocol is true while value is at a position of the MCP
// protocol.
func maskStrings(value any, patterns []string, protocol bool) (any, bool) {
	switch v := value.(type) {
	case string:
		return maskText(v, patterns)
	case []any:
		return maskItems(v, patterns, protocol)
	case map[string]any:
		return maskObject(v, patterns, protocol)
	}
	return value, false
}

func maskItems(items []any, patterns []string, protocol bool) (any, bool) {
	changed := false
	for i, item := range items {
		masked, itemChanged := maskStrings(item, patterns, protocol)
		items[i] = masked
		changed = changed || itemChanged
	}
	return items, changed
}

func maskObject(object map[string]any, patterns []string, protocol bool) (any, bool) {
	changed := false
	out := make(map[string]any, len(object))
	for _, key := range sortedKeys(object) {
		item := object[key]
		if !(protocol && slices.Contains(protocolKeys, key)) {
			masked, keyChanged := maskText(key, patterns)
			key = masked
			changed = changed || keyChanged
		}
		if protocol && exemptValue(key, item) {
			out[key] = item
			continue
		}
		masked, itemChanged := maskStrings(item, patterns, isProtocolChild(key, item, protocol))
		out[key] = masked
		changed = changed || itemChanged
	}
	return out, changed
}

// isProtocolChild reports whether the value under key is still a protocol position.
func isProtocolChild(key string, item any, protocol bool) bool {
	if !protocol {
		return false
	}
	if slices.Contains(protocolDescend, key) {
		return true
	}
	_, isList := item.([]any)
	return key == "arguments" && isList
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// exemptValue reports whether a protocol value (or a list of them, such as
// audience) is left as it is.
func exemptValue(key string, item any) bool {
	switch v := item.(type) {
	case string:
		return isProtocolValue(key, v)
	case []any:
		return key == "audience" && allProtocolValues(key, v)
	}
	return false
}

func allProtocolValues(key string, items []any) bool {
	for _, item := range items {
		text, ok := item.(string)
		if !ok || !isProtocolValue(key, text) {
			return false
		}
	}
	return true
}

// isProtocolValue reports whether text under key is a protocol word or
// identifier the agent must send back or the client must parse unchanged.
// Masking it would break the next call, so a value of the right shape is left
// alone.
func isProtocolValue(key, text string) bool {
	switch key {
	case "type", "role", "resultType", "theme", "audience":
		return isWord(text, "")
	case "name":
		return isWord(text, ".:/")
	case "mimeType":
		return isWord(text, ".+/") && strings.Count(text, "/") == 1
	}
	return false
}

// isWord reports whether text is a non-empty word of letters, digits, '_' and
// '-', plus the characters in extra.
func isWord(text, extra string) bool {
	if text == "" || len(text) > maxProtocolWordLen {
		return false
	}
	for _, c := range text {
		if !isWordRune(c, extra) {
			return false
		}
	}
	return true
}

func isWordRune(c rune, extra string) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '-' || strings.ContainsRune(extra, c)
}
