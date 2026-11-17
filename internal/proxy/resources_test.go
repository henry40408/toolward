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
