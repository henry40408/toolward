package mcpwire

import (
	"bytes"
	"encoding/json"
)

const jsonRPCVersion = "2.0"

type messageKind int

const (
	kindInvalid messageKind = iota
	kindRequest
	kindNotification
	kindResponse
)

// message is any JSON-RPC message as it arrives. Which fields are set tells
// the kind.
type message struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

func decodeMessage(raw []byte) (message, error) {
	var msg message
	if err := json.Unmarshal(raw, &msg); err != nil {
		return message{}, err
	}
	return msg, nil
}

func (m message) hasID() bool {
	return len(m.ID) > 0 && !bytes.Equal(m.ID, []byte("null"))
}

func (m message) kind() messageKind {
	switch {
	case m.Method != "" && m.hasID():
		return kindRequest
	case m.Method != "":
		return kindNotification
	case m.hasID():
		return kindResponse
	}
	return kindInvalid
}

// idKey is the form of a request id used as a map key.
func idKey(id json.RawMessage) string {
	var compact bytes.Buffer
	if err := json.Compact(&compact, id); err != nil {
		return string(id)
	}
	return compact.String()
}

type outgoing struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

func encodeRequest(id json.RawMessage, method string, params json.RawMessage) ([]byte, error) {
	return json.Marshal(outgoing{JSONRPC: jsonRPCVersion, ID: id, Method: method, Params: params})
}

func encodeNotification(method string, params json.RawMessage) ([]byte, error) {
	return json.Marshal(outgoing{JSONRPC: jsonRPCVersion, Method: method, Params: params})
}

func encodeResult(id json.RawMessage, result json.RawMessage) ([]byte, error) {
	if len(result) == 0 {
		result = json.RawMessage("{}")
	}
	return json.Marshal(outgoing{JSONRPC: jsonRPCVersion, ID: id, Result: result})
}

func encodeError(id json.RawMessage, rpcErr *Error) ([]byte, error) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return json.Marshal(outgoing{JSONRPC: jsonRPCVersion, ID: id, Error: rpcErr})
}
