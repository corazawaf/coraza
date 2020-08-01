package transformations
import (
	pcre"github.com/gijsbers/go-pcre"
)

func RemoveNulls(data string) string{
	re := pcre.MustCompile(`\x00`, 0)
	return re.ReplaceAllString(data, "", 0)
}