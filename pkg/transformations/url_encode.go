package transformations
import (
	"net/url"
)

func UrlEncode(data string) string{
	return url.QueryEscape(data)
}