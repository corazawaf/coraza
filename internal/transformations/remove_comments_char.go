// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

func removeCommentsChar(data string) (string, error) {
	value := []byte(data)
	for i := 0; i < len(value); {
		switch {
		case value[i] == '/' && (i+1 < len(value)) && value[i+1] == '*':
			value = erase(value, i, 2)
		case value[i] == '*' && (i+1 < len(value)) && value[i+1] == '/':
			value = erase(value, i, 2)
		case value[i] == '<' &&
			(i+1 < len(value)) &&
			value[i+1] == '!' &&
			(i+2 < len(value)) &&
			value[i+2] == '-' &&
			(i+3 < len(value)) &&
			value[i+3] == '-':
			value = erase(value, i, 4)
		case value[i] == '-' &&
			(i+1 < len(value)) && value[i+1] == '-' &&
			(i+2 < len(value)) && value[i+2] == '>':
			value = erase(value, i, 3)
		case value[i] == '-' && (i+1 < len(value)) && value[i+1] == '-':
			value = erase(value, i, 2)
		case value[i] == '#':
			value = erase(value, i, 1)
		default:
			i++
		}
	}
	return string(value), nil
}

func erase(str []byte, i int, count int) []byte {
	// TODO There are better algorithms to do this but not today
	var res []byte
	res = append(res, str[0:i]...)
	res = append(res, str[i+count:]...)
	return res
}
