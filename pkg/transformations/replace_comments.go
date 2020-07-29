package transformations
import (
	pcre"github.com/gijsbers/go-pcre"
)

func ReplaceComments(data string) string{
	re := pcre.MustCompile(`\/\*(.*?)\*\/`, 0)
	data = string(re.ReplaceAll([]byte(data), []byte{' '}, 0))
	return data
}