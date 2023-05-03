// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"strconv"
)

func length(data string) (string, bool, error) {
	transformedData := strconv.Itoa(len(data))
	return transformedData, true, nil
}
