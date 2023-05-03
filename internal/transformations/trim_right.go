// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "strings"

func trimRight(data string) (string, bool, error) {
	transformedData := strings.TrimRight(data, trimSpaces)
	return transformedData, len(data) != len(transformedData), nil
}
