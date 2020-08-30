package transformations
import (
	"crypto/md5"
	"io"
)

func Md5(data string) string{
	h := md5.New()
	io.WriteString(h, data)
	return string(h.Sum(nil))
	//return fmt.Sprintf("%x", h.Sum(nil))
}