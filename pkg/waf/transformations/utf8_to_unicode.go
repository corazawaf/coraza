package transformations

import (
	"fmt"
	"net/url"
	"strconv"
)

func Utf8ToUnicode(str string) string {
	data, err := url.QueryUnescape(str)
	if err != nil {
		fmt.Println("Invalid UTF8 url encoded string ", str, " try to use urlDecodeUni before")
		//data = UrlDecodeUni(str)
		return str
	}
	res := ""
	for _, s := range data {
		res += runeToAscii(s)
	}
	return res
}

func runeToAscii(r rune) string {
	if r < 128 {
		return string(r)
	} else {
		return "%u" + strconv.FormatInt(int64(r), 16)
	}
}