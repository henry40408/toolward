package names

import (
	"os"
	"strings"
	"testing"
)

// The golden file was produced by the hand-written encoder. Tool names that
// end up in users' MCP configs depend on these exact bytes.
func TestBase32PrefixMatchesGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/base32_golden.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	got := goldenLines()
	if len(got) != len(want) {
		t.Fatalf("got %d cases, golden has %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("case %d: got %q, want %q", i, got[i], want[i])
		}
	}
}
