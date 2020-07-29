package transformations
import (
	pcre"github.com/gijsbers/go-pcre"
)

func CompressWhitespace(data string) string{
	re := pcre.MustCompile(`\s\s+`, 0)
	return re.ReplaceAllString(data, " ", 0)
}