// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"encoding/base64"
)

func base64encode(data string) (string, bool, error) {
	src := []byte(data)

	return base64.StdEncoding.EncodeToString(src), true, nil
}
