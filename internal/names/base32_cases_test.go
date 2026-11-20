package names

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
)

// base32Inputs lists the digests pinned by testdata/base32_golden.txt.
func base32Inputs() [][]byte {
	var inputs [][]byte
	for length := 0; length <= 40; length++ {
		inputs = append(inputs,
			make([]byte, length),
			bytes.Repeat([]byte{0xFF}, length),
			ascending(length),
		)
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for range 500 {
		digest := make([]byte, rng.IntN(65))
		for i := range digest {
			digest[i] = byte(rng.IntN(256))
		}
		inputs = append(inputs, digest)
	}
	return inputs
}

func ascending(length int) []byte {
	digest := make([]byte, length)
	for i := range digest {
		digest[i] = byte(i * 7)
	}
	return digest
}

// base32Lengths returns the prefix lengths tried for a digest: around the
// number of complete characters it holds, and beyond it.
func base32Lengths(digestLen int) []int {
	full := digestLen * 8 / 5
	return []int{0, 1, full - 1, full, full + 1, full + 3, 52}
}

func goldenLines() []string {
	var lines []string
	for _, digest := range base32Inputs() {
		for _, n := range base32Lengths(len(digest)) {
			if n < 0 {
				continue
			}
			lines = append(lines, fmt.Sprintf("%s %d %s", hex.EncodeToString(digest), n, base32Prefix(digest, n)))
		}
	}
	return lines
}
