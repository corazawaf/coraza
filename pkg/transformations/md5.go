package transformations
import (
	"crypto/md5"
	"fmt"
	"io"
)

func Md5(data string) string{
	h := md5.New()
	io.WriteString(h, data)
	return fmt.Sprintf("%x", h.Sum(nil))
}