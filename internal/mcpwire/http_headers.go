package mcpwire

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

const (
	headerSessionID       = "Mcp-Session-Id"
	headerProtocolVersion = "Mcp-Protocol-Version"
	headerMethod          = "Mcp-Method"
	headerName            = "Mcp-Name"
	headerLastEventID     = "Last-Event-Id"

	base64HeaderPrefix = "=?base64?"
	base64HeaderSuffix = "?="
)

// nameFields maps the methods that name their target in a header to the field
// of the params that holds the name.
var nameFields = map[string]string{
	"tools/call":            "name",
	"prompts/get":           "name",
	"resources/read":        "uri",
	"resources/subscribe":   "uri",
	"resources/unsubscribe": "uri",
	"tasks/get":             "taskId",
	"tasks/update":          "taskId",
	"tasks/cancel":          "taskId",
}

// protocolVersionOf is the version a message is sent under: the one in its own
// meta when stateless, else the one the handshake agreed on.
func protocolVersionOf(msg message, negotiated string) string {
	if version, ok := metaVersion(requestMeta(msg.Params)); ok {
		return version
	}
	return negotiated
}

// setProtocolHeaders adds the headers that tell the server the version, and
// from 2026-07-28 on the method and target, so that proxies can route the
// request without reading the body.
func setProtocolHeaders(header http.Header, msg message, negotiated string) {
	version := protocolVersionOf(msg, negotiated)
	if version == "" {
		return
	}
	header.Set(headerProtocolVersion, version)
	if msg.Method == "" || hasInitialize(version) {
		return
	}
	header.Set(headerMethod, msg.Method)
	if name, ok := targetName(msg); ok {
		header.Set(headerName, encodeHeaderValue(name))
	}
}

func targetName(msg message) (string, bool) {
	field, ok := nameFields[msg.Method]
	if !ok {
		return "", false
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(msg.Params, &params) != nil {
		return "", false
	}
	var name string
	if json.Unmarshal(params[field], &name) != nil {
		return "", false
	}
	return name, true
}

// encodeHeaderValue wraps a value that cannot travel as a plain header value
// in base64.
func encodeHeaderValue(value string) string {
	if !needsBase64(value) {
		return value
	}
	return base64HeaderPrefix + base64.StdEncoding.EncodeToString([]byte(value)) + base64HeaderSuffix
}

func needsBase64(value string) bool {
	if value == "" {
		return false
	}
	if strings.ContainsAny(value[:1], " \t") || strings.ContainsAny(value[len(value)-1:], " \t") {
		return true
	}
	for _, char := range value {
		if char < 0x20 || char > 0x7e {
			return true
		}
	}
	return strings.HasPrefix(value, base64HeaderPrefix) && strings.HasSuffix(value, base64HeaderSuffix)
}
