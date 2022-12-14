// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

func replaceNulls(data string) (string, error) {
	value := []byte(data)
	for i := 0; i < len(value); i++ {
		if value[i] == '\x00' {
			value[i] = ' '
		}
	}
	return string(value), nil
}
