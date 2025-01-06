package transformations

import (
	"encoding/hex"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

func hexDecode(data string) (string, bool, error) {
	src := []byte(data)

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
