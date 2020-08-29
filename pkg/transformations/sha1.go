package transformations
import (
	"crypto/sha1"
	"io"
)

func Sha1(data string) string{
	h := sha1.New()
	io.WriteString(h, data)
	return string(h.Sum(nil))
	//return fmt.Sprintf("%x", h.Sum(nil))
}