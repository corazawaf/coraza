package cookies

import (
	"net/textproto"
	"strings"
)

// ParseCookies parses cookies and splits in name, value pairs. Won't check for valid names nor values.
// If there are multiple cookies with the same name, it will append to the list with the same name key.
// Loosely based in the stdlib src/net/http/cookie.go
func ParseCookies(rawCookies string) map[string][]string {
	cookies := make(map[string][]string)

	if len(rawCookies) == 0 {
		return cookies
	}

	rawCookies = textproto.TrimString(rawCookies)

	var part string
	for len(rawCookies) > 0 { // continue since we have rest
		part, rawCookies, _ = strings.Cut(rawCookies, ";")
		part = textproto.TrimString(part)
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, "=")
		name = textproto.TrimString(name)
		cookies[name] = append(cookies[name], val)
	}
	return cookies
}
