package transformations
import (
	"encoding/hex"
)

func HexEncode(data string) string{
	src := []byte(data)

	return hex.EncodeToString(src)
}