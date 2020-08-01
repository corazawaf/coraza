package transformations
import (
	"crypto/sha1"
	"fmt"
	"io"
)

func Sha1(data string) string{
	h := sha1.New()
	io.WriteString(h, data)
	return fmt.Sprintf("%x", h.Sum(nil))
}