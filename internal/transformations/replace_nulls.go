// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "strings"

func replaceNulls(data string) (string, bool, error) {
	transformedData := strings.ReplaceAll(data, "\x00", " ")
	return transformedData, data != transformedData, nil
}
