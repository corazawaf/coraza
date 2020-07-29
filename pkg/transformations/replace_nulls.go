package transformations
import (
	pcre"github.com/gijsbers/go-pcre"
)

func ReplaceNulls(data string) string{
	re := pcre.MustCompile(`\u0000`, 0)
	return re.ReplaceAllString(data, " ", 0)
}