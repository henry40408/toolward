package names

import (
	"slices"
	"strings"
	"testing"
)

func assignNames(server string, originals ...string) []Pair {
	return Assign(server, originals).Names
}

func TestShortCleanNamesAreUnchanged(t *testing.T) {
	got := assignNames("github", "get_issue", "list-prs")
	want := []Pair{{"get_issue", "get_issue"}, {"list-prs", "list-prs"}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestLongNamesFitTheBudgetAndEndInAHash(t *testing.T) {
	original := "create_pull_request_review_comment_thread_reply"
	exposed := assignNames("github", original)[0].Exposed
	full := "github" + Separator + exposed
	if len(full) > Budget {
		t.Fatalf("%s is too long", full)
	}
	if !strings.HasPrefix(exposed, "create_pull_request") {
		t.Fatalf("exposed = %s", exposed)
	}
	i := strings.LastIndex(exposed, "_")
	stem, hash := exposed[:i], exposed[i+1:]
	if len(hash) != HashLen {
		t.Fatalf("hash %q has the wrong length", hash)
	}
	for _, c := range hash {
		if !strings.ContainsRune(alphabet, c) {
			t.Fatalf("hash %q has a character outside the alphabet", hash)
		}
	}
	if !strings.HasPrefix(original, stem) {
		t.Fatalf("stem %q is not a prefix of the original", stem)
	}
}

func TestNamesAreStableAndDependOnTheServer(t *testing.T) {
	original := "create_pull_request_review_comment_thread_reply"
	if !slices.Equal(assignNames("github", original), assignNames("github", original)) {
		t.Fatal("names are not stable")
	}
	if slices.Equal(assignNames("github", original), assignNames("gitlab", original)) {
		t.Fatal("names do not depend on the server")
	}
}

func TestNamesSharingAPrefixStayApart(t *testing.T) {
	got := assignNames("github",
		"create_pull_request_review_comment_thread_reply",
		"create_pull_request_review_comment_thread_resolve")
	if got[0].Exposed == got[1].Exposed {
		t.Fatalf("both are %s", got[0].Exposed)
	}
}

func TestUnsafeCharactersAreReplacedAndHashed(t *testing.T) {
	got := assignNames("s", "a.b", "a:b", "a_b")
	if !strings.HasPrefix(got[0].Exposed, "a_b_") || !strings.HasPrefix(got[1].Exposed, "a_b_") {
		t.Fatalf("got %v", got)
	}
	if got[0].Exposed == got[1].Exposed {
		t.Fatal("hashed names collide")
	}
	// The clean name is left alone and cannot collide with the others.
	if got[2].Exposed != "a_b" {
		t.Fatalf("clean name became %q", got[2].Exposed)
	}
	for _, p := range got {
		if Sanitize(p.Exposed) != p.Exposed {
			t.Fatalf("%q is not sanitized", p.Exposed)
		}
	}
}

func TestSanitizeWorksPerCharacter(t *testing.T) {
	if got := Sanitize("é.ü"); got != "___" {
		t.Fatalf("got %q", got)
	}
}

func TestANameAtTheBudgetEdgeIsKept(t *testing.T) {
	room := Budget - len("s") - len(Separator)
	fits := strings.Repeat("a", room)
	over := strings.Repeat("a", room+1)
	got := assignNames("s", fits, over)
	if got[0].Exposed != fits {
		t.Fatalf("a name that fits was changed to %q", got[0].Exposed)
	}
	if got[1].Exposed == over {
		t.Fatal("a name that is too long was kept")
	}
	if len("s__"+got[1].Exposed) > Budget {
		t.Fatalf("%q is too long", got[1].Exposed)
	}
}

func TestCollisionsAreResolvedWithALongerHash(t *testing.T) {
	// Digests that agree in the first 40 bits (8 characters) only.
	digest := func(_, tool string) []byte {
		b := make([]byte, 32)
		if strings.Contains(tool, ":") {
			b[5] = 0xff
		}
		return b
	}
	// Both sanitize to the same stem "a_x".
	got := assignWith("s", []string{"a.x", "a:x"}, digest)
	if len(got.Dropped) != 0 {
		t.Fatalf("dropped %v", got.Dropped)
	}
	if got.Names[0].Exposed == got.Names[1].Exposed {
		t.Fatal("names still collide")
	}
	if len(got.Names[0].Exposed) <= len("a_x_")+HashLen {
		t.Fatalf("hash did not grow: %q", got.Names[0].Exposed)
	}
}

func TestIndistinguishableNamesAreDropped(t *testing.T) {
	got := Assign("s", []string{"dup", "dup"})
	if len(got.Names) != 1 {
		t.Fatalf("names = %v", got.Names)
	}
	if !slices.Equal(got.Dropped, []string{"dup"}) {
		t.Fatalf("dropped = %v", got.Dropped)
	}
}

func TestEmptyNamesDoNotPanic(t *testing.T) {
	got := assignNames("s", "")
	if !strings.HasPrefix(got[0].Exposed, "_") {
		t.Fatalf("got %q", got[0].Exposed)
	}
}

func TestBase32PrefixUsesTheLowercaseAlphabet(t *testing.T) {
	tests := []struct {
		digest []byte
		n      int
		want   string
	}{
		{[]byte{0, 0, 0, 0, 0}, 8, "aaaaaaaa"},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff}, 8, "77777777"},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff}, 3, "777"},
	}
	for _, tc := range tests {
		if got := base32Prefix(tc.digest, tc.n); got != tc.want {
			t.Errorf("base32Prefix(%v, %d) = %q, want %q", tc.digest, tc.n, got, tc.want)
		}
	}
}

func TestDigestSeparatesServerAndTool(t *testing.T) {
	d := sha256Digest("s", "t")
	if len(d) != 32 || slices.Equal(d, sha256Digest("t", "s")) {
		t.Fatal("digest does not separate server and tool")
	}
}
