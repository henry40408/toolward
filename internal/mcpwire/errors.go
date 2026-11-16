// Package mcpwire speaks the Model Context Protocol on the wire: JSON-RPC 2.0
// framing, a request/response peer, transports and the protocol lifecycle.
//
// Results and params stay json.RawMessage. The proxy decodes only the fields it
// needs, so everything else reaches the agent unchanged.
package mcpwire

import (
	"encoding/json"
	"errors"
	"fmt"
)

// JSON-RPC and MCP error codes.
const (
	CodeParseError                      = -32700
	CodeInvalidRequest                  = -32600
	CodeMethodNotFound                  = -32601
	CodeInvalidParams                   = -32602
	CodeInternalError                   = -32603
	CodeResourceNotFound                = -32002
	CodeHeaderMismatch                  = -32020
	CodeMissingRequiredClientCapability = -32021
	CodeUnsupportedProtocolVersion      = -32022
)

// ErrClosed is returned by calls on a peer whose connection has ended.
var ErrClosed = errors.New("connection closed")

// Error is a JSON-RPC error object. It is both what a peer returns for a failed
// call and what a handler returns to make the peer answer with an error.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// NewError builds an error with the given code and message.
func NewError(code int, message string) *Error {
	return &Error{Code: code, Message: message}
}

// MethodNotFound is the answer to a method the receiver does not handle. The
// message is the method name, as in rmcp.
func MethodNotFound(method string) *Error {
	return NewError(CodeMethodNotFound, method)
}

// InvalidParams is the answer to a request whose params cannot be used.
func InvalidParams(message string) *Error {
	return NewError(CodeInvalidParams, message)
}

// InternalError is the answer to a request that failed inside the receiver.
func InternalError(message string) *Error {
	return NewError(CodeInternalError, message)
}

// Error renders the error like rmcp does, so messages read the same as before.
func (e *Error) Error() string {
	text := fmt.Sprintf("Mcp error: %d: %s", e.Code, e.Message)
	if len(e.Data) > 0 {
		text += "(" + string(e.Data) + ")"
	}
	return text
}

// asError turns any handler failure into a JSON-RPC error.
func asError(err error) *Error {
	var rpcErr *Error
	if errors.As(err, &rpcErr) {
		return rpcErr
	}
	return InternalError(err.Error())
}
