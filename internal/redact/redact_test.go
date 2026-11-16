package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

// redactJSON redacts the JSON text and decodes the result.
func redactJSON(t *testing.T, text string, secrets []string) map[string]any {
	t.Helper()
	out, err := Value(json.RawMessage(text), secrets)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	return decoded
}

func mustMarshal(t *testing.T, value any) string {
	t.Helper()
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestResultsAreMaskedInKeysBase64LowercasePercentAndLines(t *testing.T) {
	secret := "tok/en+value=x"
	pem := "-----BEGIN KEY-----\nAAAABBBBCCCCDDDD\n-----END KEY-----"
	secrets := []string{secret, pem}
	// The secret at every base64 alignment.
	b64 := func(prefix string) string { return base64Encode([]byte(prefix + secret)) }
	value := mustMarshal(t, map[string]any{
		"tok/en+value=x": "key",
		"lower":          "tok%2fen%2bvalue%3dx",
		"slash":          `tok\/en+value=x`,
		"line":           "found AAAABBBBCCCCDDDD here",
		"b0":             b64(""),
		"b1":             b64("a"),
		"b2":             b64("ab"),
	})
	out := redactJSON(t, value, secrets)
	text := mustMarshal(t, out)
	if strings.Contains(text, "tok/en") || strings.Contains(text, "AAAABBBB") {
		t.Fatal(text)
	}
	for _, key := range []string{"b0", "b1", "b2"} {
		if !strings.Contains(out[key].(string), "[REDACTED]") {
			t.Errorf("%s: %s", key, text)
		}
	}
}

func TestResultsAreMaskedInEveryEncodingAndEveryField(t *testing.T) {
	secrets := []string{`s3"cr/et`, "abc"}
	value := mustMarshal(t, map[string]any{
		"a":        `plain s3"cr/et end`,
		"b":        []any{`{"k": "s3\"cr/et"}`, "q=s3%22cr%2Fet", "abc stays"},
		`s3"cr/et`: 1,
	})
	out := redactJSON(t, value, secrets)
	list := out["b"].([]any)
	if out["a"] != "plain [REDACTED] end" {
		t.Errorf("a = %v", out["a"])
	}
	if list[0] != `{"k": "[REDACTED]"}` {
		t.Errorf("b[0] = %v", list[0])
	}
	if list[1] != "q=[REDACTED]" {
		t.Errorf("b[1] = %v", list[1])
	}
	// Too short to mask without hitting ordinary text.
	if list[2] != "abc stays" {
		t.Errorf("b[2] = %v", list[2])
	}
	if _, ok := out["[REDACTED]"]; !ok {
		t.Errorf("the key was not masked: %v", out)
	}
}

func TestOverlappingSecretsLeaveNoFragment(t *testing.T) {
	secrets := []string{"abcdef", "defghi"}
	if got := Redact("x abcdefghi y", secrets); got != "x [REDACTED] y" {
		t.Fatalf("got %q", got)
	}
	out, err := Value(json.RawMessage(`["abcdefghi"]`), secrets)
	if err != nil || string(out) != `["[REDACTED]"]` {
		t.Fatalf("got %s, %v", out, err)
	}
}

func TestASecretThatIsACommonWordCannotBreakTheProtocol(t *testing.T) {
	out := redactJSON(t, `{"type": "text", "text": "a text", "mimeType": "text/plain", "text/odd": 1}`,
		[]string{"text"})
	if out["type"] != "text" || out["mimeType"] != "text/plain" {
		t.Errorf("protocol values changed: %v", out)
	}
	if out["text"] != "a [REDACTED]" {
		t.Errorf("text = %v", out["text"])
	}
	if out["[REDACTED]/odd"] != float64(1) {
		t.Errorf("odd key not masked: %v", out)
	}
}

func TestFreeFormDataIsMaskedEvenUnderProtocolNames(t *testing.T) {
	value := `{
		"content": [{"type": "text", "text": "x"}],
		"structuredContent": {"credentials": [
			{"name": "ghp_abcdef", "type": "Bearer ghp_abcdef", "mimeType": "a/b; t=ghp_abcdef"}]},
		"_meta": {"name": "ghp_abcdef"}
	}`
	out, err := Value(json.RawMessage(value), []string{"ghp_abcdef"})
	if err != nil || strings.Contains(string(out), "ghp_abcdef") {
		t.Fatalf("got %s, %v", out, err)
	}
}

func TestEnumValuesSurviveAWordSecret(t *testing.T) {
	value := `{"content": [{"type": "text", "text": "hi user",
		"annotations": {"audience": ["user", "assistant"]}}]}`
	out := redactJSON(t, value, []string{"user", "dark"})
	item := out["content"].([]any)[0].(map[string]any)
	audience := item["annotations"].(map[string]any)["audience"].([]any)
	if audience[0] != "user" {
		t.Errorf("audience = %v", audience)
	}
	if item["text"] != "hi [REDACTED]" {
		t.Errorf("text = %v", item["text"])
	}
}

func TestOverlappingMultibyteSecretsDoNotPanic(t *testing.T) {
	secrets := []string{"日本語パス", "語パスワード"}
	if got := Redact("a日本語パスワードb", secrets); got != "a[REDACTED]b" {
		t.Fatalf("got %q", got)
	}
}

func TestJSONInsideJSONIsMasked(t *testing.T) {
	secrets := []string{`pa"ss`}
	inner := mustMarshal(t, map[string]any{"k": `pa"ss`})
	outer := mustMarshal(t, map[string]any{"doc": inner})
	value := mustMarshal(t, map[string]any{"deep": outer})
	out, err := Value(json.RawMessage(value), secrets)
	if err != nil || strings.Contains(string(out), "pa") {
		t.Fatalf("got %s, %v", out, err)
	}
}

func TestUntouchedValuesKeepTheirKeyOrder(t *testing.T) {
	value := json.RawMessage(`{"z": 1, "a": 2, "m": "plain"}`)
	out, err := Value(value, []string{"secret-value"})
	if err != nil || string(out) != string(value) {
		t.Fatalf("got %s, %v", out, err)
	}
}

func TestChangedValuesKeepNumbersExactAndSkipHTMLEscaping(t *testing.T) {
	value := json.RawMessage(`{"big": 12345678901234567890, "f": 1.50, "t": "<a> & secret-value"}`)
	out, err := Value(value, []string{"secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"big":12345678901234567890,"f":1.50,"t":"<a> & [REDACTED]"}`
	if string(out) != want {
		t.Fatalf("got %s, want %s", out, want)
	}
}

func TestAResultThatIsNotJSONFailsClosed(t *testing.T) {
	_, err := Value(json.RawMessage(`{"a": `), []string{"secret-value"})
	if err != ErrCannotInspect {
		t.Fatalf("got %v", err)
	}
	_, err = Value(json.RawMessage(`{} {}`), []string{"secret-value"})
	if err != ErrCannotInspect {
		t.Fatalf("trailing data: got %v", err)
	}
}

func TestNoUsableSecretsReturnsTheValueUntouched(t *testing.T) {
	value := json.RawMessage(`not even json`)
	out, err := Value(value, []string{"abc", ""})
	if err != nil || string(out) != string(value) {
		t.Fatalf("got %s, %v", out, err)
	}
}

func TestRedactMasksEverySecretLongestFirst(t *testing.T) {
	secrets := []string{"abc", "abcdef", ""}
	if got := Redact("token=abcdef and abc!", secrets); got != "token=[REDACTED] and [REDACTED]!" {
		t.Fatalf("got %q", got)
	}
	if got := Redact("nothing here", secrets); got != "nothing here" {
		t.Fatalf("got %q", got)
	}
}

func TestMatchesDoNotOverlapWithinOnePattern(t *testing.T) {
	if got := Redact("aaa", []string{"aa"}); got != "[REDACTED]a" {
		t.Fatalf("got %q", got)
	}
}

// Fixed vectors: a test that encodes with base64Encode itself cannot notice a
// mistake in it, because the secret and the data go wrong alike.
func TestBase64EncodeMatchesRFC4648WithoutPadding(t *testing.T) {
	cases := [][2]string{
		{"", ""}, {"f", "Zg"}, {"fo", "Zm8"}, {"foo", "Zm9v"},
		{"foob", "Zm9vYg"}, {"fooba", "Zm9vYmE"}, {"foobar", "Zm9vYmFy"},
	}
	for _, c := range cases {
		if got := base64Encode([]byte(c[0])); got != c[1] {
			t.Errorf("%q: got %q, want %q", c[0], got, c[1])
		}
	}
	if got := base64Encode([]byte{0xfb, 0xff, 0xfe}); got != "+//+" {
		t.Errorf("got %q", got)
	}
}

func TestBase64FormsAppearInDataAtEveryAlignment(t *testing.T) {
	// One byte is too short to own a whole base64 character at some
	// alignments, so it may yield fewer forms, but never an empty one.
	for _, form := range base64Forms([]byte("a")) {
		if form == "" {
			t.Fatal("empty form")
		}
	}
	for _, secret := range []string{"ab", "abc", "tok/en+value=x"} {
		forms := base64Forms([]byte(secret))
		for before := range 3 {
			for after := range 3 {
				data := strings.Repeat("p", before) + secret + strings.Repeat("s", after)
				encoded := base64Encode([]byte(data))
				if !containsAny(encoded, forms) {
					t.Errorf("%s with %d before and %d after: %v not in %s", secret, before, after, forms, encoded)
				}
			}
		}
	}
}

func containsAny(text string, forms []string) bool {
	for _, form := range forms {
		if form != "" && strings.Contains(text, form) {
			return true
		}
	}
	return false
}

func TestProtocolValuesMustHaveTheShapeOfTheirKey(t *testing.T) {
	long := strings.Repeat("a", 129)
	limit := strings.Repeat("a", 128)
	cases := []struct {
		key, text string
		want      bool
	}{
		{"type", "text", true},
		{"type", "a_b-c9", true},
		{"type", limit, true},
		{"type", long, false},
		{"type", "", false},
		{"type", "a b", false},
		{"type", "a.b", false},
		{"role", "assistant", true},
		{"audience", "user", true},
		{"name", "ns.tool:v1/x", true},
		{"name", "a b", false},
		{"name", "", false},
		{"mimeType", "text/plain", true},
		{"mimeType", "application/ld+json", true},
		{"mimeType", "textplain", false},
		{"mimeType", "a/b/c", false},
		{"mimeType", "a b/c", false},
		{"other", "text", false},
	}
	for _, c := range cases {
		if got := isProtocolValue(c.key, c.text); got != c.want {
			t.Errorf("%s=%q: got %v, want %v", c.key, c.text, got, c.want)
		}
	}
}

func TestAnAudienceListIsExemptOnlyWhenEveryEntryIs(t *testing.T) {
	cases := []struct {
		key  string
		item any
		want bool
	}{
		{"audience", []any{"user", "assistant"}, true},
		{"audience", []any{"user", "a b"}, false},
		{"audience", []any{"user", float64(1)}, false},
		{"type", []any{"user"}, false},
		{"type", float64(1), false},
	}
	for _, c := range cases {
		if got := exemptValue(c.key, c.item); got != c.want {
			t.Errorf("%s=%v: got %v, want %v", c.key, c.item, got, c.want)
		}
	}
}

func TestPromptArgumentListsKeepTheirNamesButArgumentObjectsAreMasked(t *testing.T) {
	secrets := []string{"text"}
	list := redactJSON(t, `{"arguments": [{"name": "text"}]}`, secrets)
	if name := list["arguments"].([]any)[0].(map[string]any)["name"]; name != "text" {
		t.Errorf("list name = %v", name)
	}
	// A tool call's arguments are free-form data, not protocol.
	call := redactJSON(t, `{"arguments": {"name": "text"}}`, secrets)
	if name := call["arguments"].(map[string]any)["name"]; name != "[REDACTED]" {
		t.Errorf("call name = %v", name)
	}
}

func TestJSONEscapeFollowsSerde(t *testing.T) {
	cases := map[string]string{
		"a\"b\\c":    `a\"b\\c`,
		"\n\t\r\b\f": `\n\t\r\b\f`,
		"\x01\x1f":   `\u0001\u001f`,
		"<>& é/":     "<>& é/",
		"\x7f":       "\x7f",
	}
	for in, want := range cases {
		if got := jsonEscape(in); got != want {
			t.Errorf("jsonEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPercentEncodingCoversBothCases(t *testing.T) {
	if got := percentEncode("a/b c~é", upperHex); got != "a%2Fb%20c~%C3%A9" {
		t.Errorf("upper = %q", got)
	}
	if got := percentEncode("a/b c~é", lowerHex); got != "a%2fb%20c~%c3%a9" {
		t.Errorf("lower = %q", got)
	}
}

func TestMultiLineSecretsAlsoMaskEachLongLine(t *testing.T) {
	got := secretsWithLines([]string{"abc", "short\n  long-enough-line  \r\nx"})
	want := []string{"short\n  long-enough-line  \r\nx", "long-enough-line"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %q", got)
	}
}

func TestPatternsAreLongestFirstAndAtLeastFourBytes(t *testing.T) {
	patterns := resultPatterns([]string{"tok/en+value=x"})
	for i, p := range patterns {
		if len(p) < minResultSecretLen {
			t.Errorf("short pattern %q", p)
		}
		if i > 0 && len(p) > len(patterns[i-1]) {
			t.Errorf("%q is longer than %q before it", p, patterns[i-1])
		}
	}
}
