// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"encoding/base64"
)

func base64Encode(data string) (string, bool, error) {
	return base64.StdEncoding.EncodeToString([]byte(data)), true, nil
}
