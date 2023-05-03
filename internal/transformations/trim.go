// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "strings"

// from https://en.cppreference.com/w/cpp/string/byte/isspace
// - space (0x20, ' ')
// - form feed (0x0c, '\f')
// - line feed (0x0a, '\n')
// - carriage return (0x0d, '\r')
// - horizontal tab (0x09, '\t')
// - vertical tab (0x0b, '\v')

const trimSpaces = " \t\n\r\f\v"

func trim(data string) (string, bool, error) {
	transformedData := strings.Trim(data, trimSpaces)
	return transformedData, len(data) != len(transformedData), nil
}
