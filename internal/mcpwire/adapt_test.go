package mcpwire

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestAdaptToPeerDropsResultTypeCompleteForOlderConnections(t *testing.T) {
	cases := map[string]struct {
		result string
		inline bool
		want   string
	}{
		"older connection":   {`{"a":1,"resultType":"complete","b":2}`, false, `{"a":1,"b":2}`},
		"inline connection":  {`{"a":1,"resultType":"complete"}`, true, `{"a":1,"resultType":"complete"}`},
		"other result types": {`{"resultType":"task"}`, false, `{"resultType":"task"}`},
		"no result type":     {`{"a":1}`, false, `{"a":1}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := adaptToPeer(json.RawMessage(tc.result), nil, tc.inline)
			if err != nil || string(got) != tc.want {
				t.Errorf("got %s, %v, want %s", got, err, tc.want)
			}
		})
	}
}

func TestAdaptToPeerMapsResourceNotFoundForInlineConnections(t *testing.T) {
	missing := NewError(CodeResourceNotFound, "gone")
	_, err := adaptToPeer(nil, missing, true)
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != CodeInvalidParams || rpcErr.Message != "gone" {
		t.Errorf("inline: %v", err)
	}
	if missing.Code != CodeResourceNotFound {
		t.Error("the original error was changed")
	}
	_, err = adaptToPeer(nil, missing, false)
	if !errors.As(err, &rpcErr) || rpcErr.Code != CodeResourceNotFound {
		t.Errorf("older: %v", err)
	}
}
