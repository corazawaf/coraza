// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"unicode"
)

/*
https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/actions/transformations/cmd_line.cc
Copied from modsecurity
deleting all backslashes [\]
deleting all double quotes ["]
deleting all single quotes [']
deleting all carets [^]
deleting spaces before a slash /
deleting spaces before an open parentesis [(]
replacing all commas [,] and semicolon [;] into a space
replacing all multiple spaces (including tab, newline, etc.) into one space
transform all characters to lowercase
*/
func cmdLine(data string) (string, error) {
	space := false
	ret := []byte{}
	for _, a := range data {
		switch {
		case a == '"' || a == '\'' || a == '\\' || a == '^':
			/* remove some characters */
		case a == ' ' || a == ',' || a == ';' || a == '\t' || a == '\r' || a == '\n':
			/* replace some characters to space (only one) */
			if !space {
				ret = append(ret, ' ')
				space = true
			}
		case a == '/' || a == '(':
			/* remove space before / or ( */
			if space {
				ret = ret[:len(ret)-1]
			}
			space = false

			ret = append(ret, byte(a))
		default:
			b := unicode.ToLower(a)
			ret = append(ret, byte(b))
			space = false
		}
	}
	return string(ret), nil
}
