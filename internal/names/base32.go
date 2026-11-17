package names

const alphabet = "abcdefghijklmnopqrstuvwxyz234567"

// base32Prefix encodes the first n characters of digest with the lowercase
// RFC 4648 alphabet and no padding.
func base32Prefix(digest []byte, n int) string {
	out := make([]byte, 0, n)
	var buffer uint32
	bits := 0
	for _, b := range digest {
		buffer = buffer<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, alphabet[(buffer>>bits)&31])
			if len(out) == n {
				return string(out)
			}
		}
		buffer &= 1<<bits - 1
	}
	return string(out)
}
