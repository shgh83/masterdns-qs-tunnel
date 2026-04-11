package base32x

import (
	"encoding/base32"
	"fmt"
	"strings"
)

var (
	lowerEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	lookup        [256]int
	alphabetLower = []byte("abcdefghijklmnopqrstuvwxyz234567")
)

func init() {
	for i := range lookup {
		lookup[i] = -1
	}
	for i, ch := range alphabetLower {
		lookup[ch] = i
		if ch >= 'a' && ch <= 'z' {
			lookup[ch-'a'+'A'] = i
		}
	}
}

func EncodeLowerNoPadding(src []byte) []byte {
	if len(src) == 0 {
		return []byte{}
	}
	dst := make([]byte, lowerEncoding.EncodedLen(len(src)))
	lowerEncoding.Encode(dst, src)
	return dst
}

func DecodeLowerNoPadding(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return []byte{}, nil
	}
	normalized := []byte(strings.ToLower(string(src)))
	dst := make([]byte, lowerEncoding.DecodedLen(len(normalized)))
	n, err := lowerEncoding.Decode(dst, normalized)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func NumberToLowerBase32(n uint64, width int) ([]byte, error) {
	if width <= 0 {
		return nil, fmt.Errorf("width must be positive")
	}
	out := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		out[i] = alphabetLower[n&31]
		n >>= 5
	}
	if n != 0 {
		return nil, fmt.Errorf("value does not fit in %d base32 chars", width)
	}
	return out, nil
}

func Base32ToNumber(src []byte) (uint64, error) {
	var n uint64
	for _, ch := range src {
		idx := lookup[ch]
		if idx < 0 {
			return 0, fmt.Errorf("invalid base32 character %q", ch)
		}
		n = (n << 5) | uint64(idx)
	}
	return n, nil
}
