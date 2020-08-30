package transformations
import (
	pcre"github.com/gijsbers/go-pcre"
)

func ReplaceNulls(data string) string{
	re := pcre.MustCompile(`\0`, 0)
	return re.ReplaceAllString(data, " ", 0)
}