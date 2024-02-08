// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

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

	rawCookies = textproto.TrimString(rawCookies)

	if rawCookies == "" {
		return cookies
	}

	var part string
	for len(rawCookies) > 0 { // continue since we have rest
		part, rawCookies, _ = strings.Cut(rawCookies, ";")
		part = textproto.TrimString(part)
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, "=")
		name = textproto.TrimString(name)
		// if name is empty (eg: "Cookie:   =foo;") skip it
		if name == "" {
			continue
		}
		cookies[name] = append(cookies[name], val)
	}
	return cookies
}
