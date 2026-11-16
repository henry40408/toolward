package importer

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/tailscale/hujson"
)

// object is a JSON object. Encoding sorts its keys, as serde_json does without
// its preserve_order feature.
type object = map[string]any

// parseDocument reads JSONC. Numbers stay as written (json.Number). Text that
// holds only whitespace and comments is null, like an empty file.
func parseDocument(text string) (any, error) {
	standard, err := hujson.Standardize([]byte(text))
	if err != nil {
		if isBlank(text) {
			return nil, nil
		}
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(standard))
	decoder.UseNumber()
	var value any
	err = decoder.Decode(&value)
	return value, err
}

func isBlank(text string) bool {
	value, err := hujson.Parse([]byte("[" + text + "\n]"))
	if err != nil {
		return false
	}
	array, ok := value.Value.(*hujson.Array)
	return ok && len(array.Elements) == 0
}

// encodeCompact writes JSON on one line, without escaping <, > and &.
func encodeCompact(value any) string {
	return strings.TrimSuffix(encode(value, ""), "\n")
}

// encodePretty writes JSON indented by two spaces, with a final newline.
func encodePretty(value any) string {
	return encode(value, "  ")
}

func encode(value any, indent string) string {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", indent)
	// Every value here came from decoding JSON, so it always encodes.
	_ = encoder.Encode(value)
	return out.String()
}

func cloneObject(source object) object {
	decoder := json.NewDecoder(strings.NewReader(encodeCompact(source)))
	decoder.UseNumber()
	var clone object
	_ = decoder.Decode(&clone)
	return clone
}

// safeError is a config error without the text that caused it, because a
// shape error quotes the value.
func safeError(err error) string {
	if strings.HasPrefix(err.Error(), "invalid config: ") {
		return "a field has the wrong type"
	}
	return err.Error()
}
