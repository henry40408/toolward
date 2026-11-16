// Package rawjson reads and edits single fields of raw JSON objects. The proxy
// uses it to rename what an upstream sent without decoding the rest, so unknown
// fields and the key order reach the agent unchanged.
package rawjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

var errNotObject = errors.New("not a JSON object")

type member struct {
	key   string
	value json.RawMessage
}

// String returns the string value of key. It is false when the key is absent
// or its value is not a string.
func String(object json.RawMessage, key string) (string, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(object, &fields) != nil {
		return "", false
	}
	var text string
	if json.Unmarshal(fields[key], &text) != nil {
		return "", false
	}
	return text, true
}

// Raw returns the value of key, or nil when the key is absent.
func Raw(object json.RawMessage, key string) json.RawMessage {
	var fields map[string]json.RawMessage
	if json.Unmarshal(object, &fields) != nil {
		return nil
	}
	return fields[key]
}

// SetString returns object with key set to text. An existing key keeps its
// place, a new one goes last.
func SetString(object json.RawMessage, key, text string) (json.RawMessage, error) {
	encoded, err := encode(text)
	if err != nil {
		return nil, err
	}
	return SetRaw(object, key, encoded)
}

// SetRaw is like SetString for a value that is already JSON.
func SetRaw(object json.RawMessage, key string, value json.RawMessage) (json.RawMessage, error) {
	members, err := members(object)
	if err != nil {
		return nil, err
	}
	replaced := false
	for i := range members {
		if members[i].key == key {
			members[i].value = value
			replaced = true
		}
	}
	if !replaced {
		members = append(members, member{key: key, value: value})
	}
	return join(members)
}

// Delete returns object without key.
func Delete(object json.RawMessage, key string) (json.RawMessage, error) {
	all, err := members(object)
	if err != nil {
		return nil, err
	}
	kept := all[:0]
	for _, m := range all {
		if m.key != key {
			kept = append(kept, m)
		}
	}
	return join(kept)
}

// Marshal is json.Marshal without escaping "<", ">" and "&", so text stays
// as it was.
func Marshal(value any) (json.RawMessage, error) {
	return encode(value)
}

// encode marshals without escaping "<", ">" and "&", so text stays as it was.
func encode(value any) (json.RawMessage, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}

func members(object json.RawMessage) ([]member, error) {
	decoder := json.NewDecoder(bytes.NewReader(object))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, errNotObject
	}
	var found []member
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errNotObject
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		found = append(found, member{key: key, value: value})
	}
	return found, nil
}

func join(members []member) (json.RawMessage, error) {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			buffer.WriteByte(',')
		}
		key, err := encode(m.key)
		if err != nil {
			return nil, fmt.Errorf("encode key: %w", err)
		}
		buffer.Write(key)
		buffer.WriteByte(':')
		buffer.Write(m.value)
	}
	buffer.WriteByte('}')
	return buffer.Bytes(), nil
}
