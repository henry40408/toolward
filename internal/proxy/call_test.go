package proxy

import (
	"encoding/json"
	"testing"
)

func TestToolResultsAreCompleted(t *testing.T) {
	cases := map[string]string{
		`{"isError":true}`:                       `{"isError":true,"content":[],"resultType":"complete"}`,
		`{"content":null,"resultType":null}`:     `{"content":[],"resultType":"complete"}`,
		`{"content":[],"resultType":"complete"}`: `{"content":[],"resultType":"complete"}`,
	}
	for in, want := range cases {
		out, err := toolResult(json.RawMessage(in))
		if err != nil || string(out) != want {
			t.Errorf("%s: got %s, %v; want %s", in, out, err, want)
		}
	}
}
