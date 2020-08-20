package transformations
import (
	pcre"github.com/gijsbers/go-pcre"
)

func CompressWhitespace(data string) string{
	re := pcre.MustCompile(`\s+`, 0)
	//TODO avoid \n, \s includes line break
	return re.ReplaceAllString(data, " ", 0)
}