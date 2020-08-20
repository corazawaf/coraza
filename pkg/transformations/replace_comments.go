package transformations
import (
	pcre"github.com/gijsbers/go-pcre"
)

func ReplaceComments(data string) string{
	re := pcre.MustCompile(`\/\*(.*?)\*\/`, 0)
	return re.ReplaceAllString(data, "", 0)
}