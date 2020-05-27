package transformations
import (
	"strconv"
)

func Length(data string) string{
	return strconv.Itoa(len(data))
}