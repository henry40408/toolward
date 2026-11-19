package proxy

import (
	"strings"
	"testing"
)

func TestURIsSurviveARoundTrip(t *testing.T) {
	for _, uri := range []string{
		"file:///a b/ü.txt?x=1&y=%20#frag",
		"https://example.com/a/b",
		"",
		"x://100%",
	} {
		exposed := exposeURI("srv", uri)
		if !strings.HasPrefix(exposed, "toolward://srv/") {
			t.Errorf("%q exposed as %q", uri, exposed)
		}
		if strings.Contains(strings.TrimPrefix(exposed, "toolward://srv/"), "/") {
			t.Errorf("%q keeps a slash: %q", uri, exposed)
		}
		server, original, ok := restoreURI(exposed)
		if !ok || server != "srv" || original != uri {
			t.Errorf("restore(%q) = %q, %q, %v", exposed, server, original, ok)
		}
	}
}

func TestForeignOrBrokenURIsAreRejected(t *testing.T) {
	for _, uri := range []string{"file:///x", "toolward://srv", "toolward://srv/%zz", "toolward://srv/%FF", "toolward://srv/%4"} {
		if server, original, ok := restoreURI(uri); ok {
			t.Errorf("%q restored as %q, %q", uri, server, original)
		}
	}
}

func TestDecodeURIAcceptsAndRejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"empty", "", "", true},
		{"plain", "abc", "abc", true},
		{"upper hex", "%41%4A%5A", "AJZ", true},
		{"lower hex", "%41%4a%5a", "AJZ", true},
		{"mixed case hex", "%4A%4a", "JJ", true},
		{"percent at end", "abc%", "", false},
		{"percent alone", "%", "", false},
		{"percent and one digit", "abc%4", "", false},
		{"percent and one digit mid", "%4", "", false},
		{"non-hex high", "%G1", "", false},
		{"non-hex low", "%1G", "", false},
		{"non-hex both", "%zz", "", false},
		{"percent then percent", "%%41", "", false},
		{"space after percent", "% 41", "", false},
		{"valid then bad", "%41%4", "", false},
		{"nul", "%00", "\x00", true},
		{"literal nul", "a\x00b", "a\x00b", true},
		{"control", "%01%1F%7F\t\n", "\x01\x1f\x7f\t\n", true},
		{"invalid utf8 FF", "%FF", "", false},
		{"overlong C0AF", "%C0%AF", "", false},
		{"surrogate EDA080", "%ED%A0%80", "", false},
		{"lone continuation", "%80", "", false},
		{"truncated multibyte", "%E2%82", "", false},
		{"valid euro", "%E2%82%AC", "€", true},
		{"valid euro lower", "%e2%82%ac", "€", true},
		{"literal non-ASCII", "ü€", "ü€", true},
		{"literal invalid utf8", "a\xffb", "", false},
		{"mixed literal and encoded", "ü%C3%BC", "üü", true},
		{"plus stays", "a+b%2Bc", "a+b+c", true},
		{"literal separators", "a/b?c#d", "a/b?c#d", true},
		{"encoded separators", "a%2Fb%3Fc%23d", "a/b?c#d", true},
		{"encoded percent", "100%25", "100%", true},
		{"encoded percent then hex", "%2541", "%41", true},
		{"colon and at", "a%3Ab%40c", "a:b@c", true},
		{"long", strings.Repeat("a%20b/", 20000), strings.Repeat("a b/", 20000), true},
	}
	for _, tc := range cases {
		got, ok := decodeURI(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: decodeURI(%.40q) = (%.40q, %v), want (%.40q, %v)", tc.name, tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
