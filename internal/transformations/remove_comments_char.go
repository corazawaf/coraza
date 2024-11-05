// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import stringsutil "github.com/corazawaf/coraza/v3/internal/strings"

func removeCommentsChar(value string) (string, bool, error) {
	inputLen := len(value)
	res := make([]byte, 0, inputLen)
	changed := false
	for i := 0; i < inputLen; {
		switch {
		case value[i] == '/' && (i+1 < inputLen) && value[i+1] == '*':
			i += 2
			changed = true
		case value[i] == '*' && (i+1 < inputLen) && value[i+1] == '/':
			i += 2
			changed = true
		case value[i] == '<' &&
			(i+1 < inputLen) &&
			value[i+1] == '!' &&
			(i+2 < inputLen) &&
			value[i+2] == '-' &&
			(i+3 < inputLen) &&
			value[i+3] == '-':
			i += 4
			changed = true
		case value[i] == '-' &&
			(i+1 < inputLen) && value[i+1] == '-' &&
			(i+2 < inputLen) && value[i+2] == '>':
			i += 3
			changed = true
		case value[i] == '-' && (i+1 < inputLen) && value[i+1] == '-':
			i += 2
			changed = true
		case value[i] == '#':
			i += 1
			changed = true
		default:
			res = append(res, value[i])
			i += 1
		}
	}
	return stringsutil.WrapUnsafe(res), changed, nil
}
