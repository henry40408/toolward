package mcpwire

import (
	"encoding/json"
	"testing"
)

func TestWithMetaAcceptsNullAndAbsentParamsAndMeta(t *testing.T) {
	entries := map[string]json.RawMessage{"k": json.RawMessage(`1`)}
	cases := map[string]struct {
		params string
		want   string
	}{
		"absent params":    {"", `{"_meta":{"k":1}}`},
		"null params":      {`null`, `{"_meta":{"k":1}}`},
		"null meta":        {`{"a":2,"_meta":null}`, `{"_meta":{"k":1},"a":2}`},
		"existing meta":    {`{"_meta":{"p":"x"}}`, `{"_meta":{"k":1,"p":"x"}}`},
		"params and meta":  {`{"a":2}`, `{"_meta":{"k":1},"a":2}`},
		"entry overridden": {`{"_meta":{"k":0}}`, `{"_meta":{"k":1}}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := withMeta(json.RawMessage(tc.params), entries)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestWithMetaRejectsParamsThatAreNotAnObject(t *testing.T) {
	if _, err := withMeta(json.RawMessage(`[1]`), nil); err == nil {
		t.Error("expected an error")
	}
	if _, err := withMeta(json.RawMessage(`{"_meta":5}`), nil); err == nil {
		t.Error("expected an error")
	}
}
