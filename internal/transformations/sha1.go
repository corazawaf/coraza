// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"crypto/sha1"
	"io"
	"sync"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

var (
	emptySHA1     string
	emptySHA1Once sync.Once
)

func sha1T(data string) (string, bool, error) {
	if len(data) == 0 {
		// Computed lazily to avoid calling SHA-1 in an init, which panics under GODEBUG=fips140=only.
		emptySHA1Once.Do(func() {
			sum := sha1.Sum(nil)
			emptySHA1 = string(sum[:])
		})
		return emptySHA1, true, nil
	}
	h := sha1.New()
	_, err := io.WriteString(h, data)
	if err != nil {
		return data, false, err
	}
	// The occurrence of an invariant transformation is so unlikely that we can assume the transformation returns a changed value
	return strings.WrapUnsafe(h.Sum(nil)), true, nil
}
