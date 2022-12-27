// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"github.com/corazawaf/coraza/v3/internal/strings"
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
	for i := 0; i < len(data); i++ {
		if needsTransform(data[i]) {
			return doCMDLine(data, i), nil
		}
	}
	return data, nil
}

func doCMDLine(input string, pos int) string {
	// Some characters will be removed so the result is likely smaller than the input,
	// but it shouldn't be much so preallocate to that anyways.
	ret := make([]byte, pos, len(input))
	copy(ret, input[:pos])

	space := false
	for i := pos; i < len(input); i++ {
		a := input[i]
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

			ret = append(ret, a)
		default:
			// Copied from unicode.ToLower
			if 'A' <= a && a <= 'Z' {
				a += 'a' - 'A'
			}
			ret = append(ret, a)
			space = false
		}
	}
	return strings.WrapUnsafe(ret)
}

func needsTransform(c byte) bool {
	if c >= 'A' && c <= 'Z' {
		return true
	}
	return c == '"' || c == '\'' || c == '\\' || c == '^' || c == ' ' || c == ',' || c == ';' || c == '\t' || c == '\r' || c == '\n' || c == '/' || c == '('
}
