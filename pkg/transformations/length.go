package transformations
import (
	"strconv"
	"unicode/utf8"
)

func Length(data string) string{
	return strconv.Itoa(utf8.RuneCountInString(data))
}