// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strconv"
	"unicode/utf8"
)

func length(data string) (string, error) {
	return strconv.Itoa(utf8.RuneCountInString(data)), nil
}
