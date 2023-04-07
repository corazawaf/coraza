// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import stringsutil "github.com/corazawaf/coraza/v3/internal/strings"

func removeCommentsChar(value string) (string, error) {
	res := make([]byte, 0, len(value))
	for i := 0; i < len(value); {
		switch {
		case value[i] == '/' && (i+1 < len(value)) && value[i+1] == '*':
			i += 2
		case value[i] == '*' && (i+1 < len(value)) && value[i+1] == '/':
			i += 2
		case value[i] == '<' &&
			(i+1 < len(value)) &&
			value[i+1] == '!' &&
			(i+2 < len(value)) &&
			value[i+2] == '-' &&
			(i+3 < len(value)) &&
			value[i+3] == '-':
			i += 4
		case value[i] == '-' &&
			(i+1 < len(value)) && value[i+1] == '-' &&
			(i+2 < len(value)) && value[i+2] == '>':
			i += 3
		case value[i] == '-' && (i+1 < len(value)) && value[i+1] == '-':
			i += 2
		case value[i] == '#':
			i += 1
		default:
			res = append(res, value[i])
			i += 1
		}
	}
	return stringsutil.WrapUnsafe(res), nil
}
