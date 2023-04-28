// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strings"
)

func lowerCase(data string) (string, bool, error) {
	transformedData := strings.ToLower(data)
	return transformedData, data != transformedData, nil
}
