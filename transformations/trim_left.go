// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "strings"

func trimLeft(data string) (string, error) {
	return strings.TrimLeft(data, " \t\n\r"), nil
}
