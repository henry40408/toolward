package mcpwire

import (
	"bytes"
	"encoding/json"
)

// Protocol versions this package knows, oldest first.
const (
	Version20241105 = "2024-11-05"
	Version20250326 = "2025-03-26"
	Version20250618 = "2025-06-18"
	Version20251125 = "2025-11-25"
	Version20260728 = "2026-07-28"
)

// KnownVersions are the protocol versions a server here accepts.
var KnownVersions = []string{
	Version20241105,
	Version20250326,
	Version20250618,
	Version20251125,
	Version20260728,
}

// The keys of the inline lifecycle that 2026-07-28 moved into each request's
// "_meta".
const (
	MetaProtocolVersion     = "io.modelcontextprotocol/protocolVersion"
	MetaClientInfo          = "io.modelcontextprotocol/clientInfo"
	MetaClientCapabilities  = "io.modelcontextprotocol/clientCapabilities"
	MetaServerInfo          = "io.modelcontextprotocol/serverInfo"
	metaField               = "_meta"
	methodInitialize        = "initialize"
	methodDiscover          = "server/discover"
	methodInitialized       = "notifications/initialized"
	emptyObject             = "{}"
	noInitializeFromVersion = Version20260728
)

// hasInitialize says whether a version negotiates by the initialize handshake.
// Versions are dates, so they compare as text.
func hasInitialize(version string) bool {
	return version < noInitializeFromVersion
}

func isKnownVersion(version string) bool {
	for _, known := range KnownVersions {
		if known == version {
			return true
		}
	}
	return false
}

// requestMeta returns the "_meta" object of request params. It is nil when
// there is none.
func requestMeta(params json.RawMessage) map[string]json.RawMessage {
	var fields map[string]json.RawMessage
	if json.Unmarshal(params, &fields) != nil {
		return nil
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(fields[metaField], &meta) != nil {
		return nil
	}
	return meta
}

// metaVersion returns the protocol version in a request's meta, when it is a
// string.
func metaVersion(meta map[string]json.RawMessage) (string, bool) {
	var version string
	if json.Unmarshal(meta[MetaProtocolVersion], &version) != nil {
		return "", false
	}
	return version, true
}

// missingMetaKeys lists the required keys that are absent or malformed.
func missingMetaKeys(meta map[string]json.RawMessage) []string {
	var missing []string
	if _, ok := metaVersion(meta); !ok {
		missing = append(missing, MetaProtocolVersion)
	}
	if !isJSONObject(meta[MetaClientCapabilities]) {
		missing = append(missing, MetaClientCapabilities)
	}
	return missing
}

func isJSONObject(raw json.RawMessage) bool {
	return bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) && json.Valid(raw)
}

// decodeObject decodes a JSON object. Absent and null input give an empty
// map that is safe to write to.
func decodeObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, err
		}
	}
	if fields == nil {
		fields = map[string]json.RawMessage{}
	}
	return fields, nil
}

// withMeta returns params with the given entries added to its "_meta", which
// they override. Other entries, such as a progress token, stay.
func withMeta(params json.RawMessage, entries map[string]json.RawMessage) (json.RawMessage, error) {
	fields, err := decodeObject(params)
	if err != nil {
		return nil, err
	}
	meta, err := decodeObject(fields[metaField])
	if err != nil {
		return nil, err
	}
	for key, value := range entries {
		meta[key] = value
	}
	encodedMeta, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	fields[metaField] = encodedMeta
	return json.Marshal(fields)
}
