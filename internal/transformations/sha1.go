// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"crypto/sha1"
	"io"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

var emptySHA1 string

func sha1T(data string) (string, bool, error) {
	if len(data) == 0 {
		return emptySHA1, false, nil
	}
	h := sha1.New()
	_, err := io.WriteString(h, data)
	if err != nil {
		return data, false, err
	}
	// The occurrence of an invariant transformation is so unlikely that we can assume the transformation returns a changed value
	return strings.WrapUnsafe(h.Sum(nil)), true, nil
}

func init() {
	buf := sha1.Sum(nil)
	emptySHA1 = string(buf[:])
}
