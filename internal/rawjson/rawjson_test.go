package rawjson

import (
	"encoding/json"
	"testing"
)

func TestStringReadsOnlyStrings(t *testing.T) {
	object := json.RawMessage(`{"name":"a<b","n":1}`)
	if got, ok := String(object, "name"); !ok || got != "a<b" {
		t.Errorf("name = %q, %v", got, ok)
	}
	for _, key := range []string{"n", "missing"} {
		if _, ok := String(object, key); ok {
			t.Errorf("%s was read as a string", key)
		}
	}
	if _, ok := String(json.RawMessage(`[1]`), "name"); ok {
		t.Error("an array has no keys")
	}
}

func TestSetStringKeepsOrderAndUnknownFields(t *testing.T) {
	cases := map[string]struct {
		object, key, text, want string
	}{
		"replace in place":  {`{"z":1,"name":"old","a":{"x":[1, 2]}}`, "name", "new", `{"z":1,"name":"new","a":{"x":[1, 2]}}`},
		"append":            {`{"z":1}`, "name", "new", `{"z":1,"name":"new"}`},
		"empty object":      {`{}`, "name", "new", `{"name":"new"}`},
		"no html escape":    {`{"name":"x"}`, "name", "a<b>&c", `{"name":"a<b>&c"}`},
		"quote and unicode": {`{"name":"x"}`, "name", "\"é\"", `{"name":"\"é\""}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := SetString(json.RawMessage(tc.object), tc.key, tc.text)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestSetStringRejectsWhatIsNotAnObject(t *testing.T) {
	for _, object := range []string{`[1]`, `"x"`, `null`, ``, `{"a":`} {
		if _, err := SetString(json.RawMessage(object), "name", "x"); err == nil {
			t.Errorf("%q: expected an error", object)
		}
	}
}
