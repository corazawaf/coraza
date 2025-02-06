package transformations

import (
	"encoding/hex"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

func hexDecode(data string) (string, bool, error) {
	dst, err := hex.DecodeString(data)
	if err != nil {
		return "", false, err
	}

	return strings.WrapUnsafe(dst), true, nil
}
