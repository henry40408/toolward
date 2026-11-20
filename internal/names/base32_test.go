package names

import "testing"

// Tool names that end up in users' MCP configs depend on these exact strings.
// The vectors are RFC 4648 lower-cased, minus the trailing partial character.
func TestBase32Prefix(t *testing.T) {
	tests := []struct {
		name   string
		digest []byte
		n      int
		want   string
	}{
		{"empty", nil, 0, ""},
		{"empty with limit", nil, 5, ""},
		{"1 byte", []byte("f"), 0, "m"},
		{"2 bytes", []byte("fo"), 0, "mzx"},
		{"3 bytes", []byte("foo"), 0, "mzxw"},
		{"4 bytes", []byte("foob"), 0, "mzxw6y"},
		{"5 bytes", []byte("fooba"), 0, "mzxw6ytb"},
		{"6 bytes", []byte("foobar"), 0, "mzxw6ytbo"},
		{"full length", []byte("foobar"), 9, "mzxw6ytbo"},
		{"limit above complete", []byte("foobar"), 99, "mzxw6ytbo"},
		{"limit below complete", []byte("foobar"), 3, "mzx"},
		{"all zero", make([]byte, 5), 0, "aaaaaaaa"},
		{"all ones", []byte{0xff, 0xff, 0xff, 0xff, 0xff}, 0, "77777777"},
		{"all ones with limit", []byte{0xff, 0xff, 0xff, 0xff, 0xff}, 3, "777"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := base32Prefix(tt.digest, tt.n); got != tt.want {
				t.Errorf("base32Prefix(%x, %d) = %q, want %q", tt.digest, tt.n, got, tt.want)
			}
		})
	}
}
