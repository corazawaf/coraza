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
func cmdLine(data string) (string, bool, error) {
	for i := 0; i < len(data); i++ {
		if needsTransform(data[i]) {
			transformed, changed := doCMDLine(data, i)
			return transformed, changed, nil
		}
	}
	return data, false, nil
}

func doCMDLine(input string, pos int) (string, bool) {
	// Some characters will be removed so the result is likely smaller than the input,
	// but it shouldn't be much so preallocate to that anyways.
	ret := make([]byte, pos, len(input))
	copy(ret, input[:pos])

	// changed tracks whether any byte was actually removed, replaced or lowercased.
	changed := false
	space := false
	for i := pos; i < len(input); i++ {
		a := input[i]
		switch a {
		case '"', '\'', '\\', '^':
			// remove some characters
			changed = true
		case ' ', ',', ';', '\t', '\r', '\n':
			/* replace some characters to space (only one) */
			if !space {
				// A non-space delimiter turned into a space is a change; a space
				// left as a space is not.
				if a != ' ' {
					changed = true
				}
				ret = append(ret, ' ')
				space = true
			} else {
				// Collapsing consecutive delimiters drops this character.
				changed = true
			}
		case '/', '(':
			/* remove space before / or ( */
			if space {
				ret = ret[:len(ret)-1]
				changed = true
			}
			space = false

			ret = append(ret, a)
		default:
			// Copied from unicode.ToLower
			if 'A' <= a && a <= 'Z' {
				a += 'a' - 'A'
				changed = true
			}
			ret = append(ret, a)
			space = false
		}
	}
	return strings.WrapUnsafe(ret), changed
}

// needsTransform only reports that a candidate character is present,
// not that the value actually changes (e.g. a '/' or '(' not preceded
// by a space is a no-op). doCMDLine has to return the changed flag.
func needsTransform(c byte) bool {
	if c >= 'A' && c <= 'Z' {
		return true
	}
	switch c {
	case '"', '\'', '\\', '^', ' ', ',', ';', '\t', '\r', '\n', '/', '(':
		return true
	default:
		return false
	}
}
