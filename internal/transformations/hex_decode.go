package transformations

import (
	"encoding/hex"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

func hexDecode(data string) (string, bool, error) {
	src := []byte(data)

	// According to RFC-4648 section 8, the valid lenght of src MUST be even.
	// Here https://datatracker.ietf.org/doc/html/rfc4648#section-8
	// There was a decision to cut "redundant" bytes for the "best effort aproach" and proceed decoding.
	if len(src)%2 != 0 {
		src = src[:len(src)-1]
	}
	dst := make([]byte, hex.DecodedLen(len(src)))

	_, err := hex.Decode(dst, src)
	if err != nil {
		return "", false, err
	}

	return strings.WrapUnsafe(dst), true, nil
}
