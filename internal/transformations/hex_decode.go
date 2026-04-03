// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"encoding/hex"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

func hexDecode(data string) (string, bool, error) {
	dst, err := hex.DecodeString(data)
	if err != nil {
		return "", false, err
	}

	return strings.WrapUnsafe(dst), true, nil
}
