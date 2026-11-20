package names

import "encoding/base32"

const alphabet = "abcdefghijklmnopqrstuvwxyz234567"

var lowerBase32 = base32.NewEncoding(alphabet).WithPadding(base32.NoPadding)

// base32Prefix encodes the first n characters of digest with the lowercase
// RFC 4648 alphabet and no padding.
func base32Prefix(digest []byte, n int) string {
	// The encoder emits a final partial character that carries fewer than 5
	// digest bits; names have never included it, so cap n at the complete ones.
	// n == 0 has always meant "no limit".
	complete := len(digest) * 8 / 5
	if n == 0 || n > complete {
		n = complete
	}
	return lowerBase32.EncodeToString(digest)[:n]
}
