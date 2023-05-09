// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"encoding/hex"
)

func hexEncode(data string) (string, bool, error) {
	src := []byte(data)

	return hex.EncodeToString(src), true, nil
}
