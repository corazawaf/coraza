// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"crypto/sha1"
	"io"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

// The SHA-1 digest of an empty input, hardcoded rather than computed via
// sha1.Sum(nil): that call panics under GODEBUG=fips140=only, even lazily,
// since crypto/sha1's checkSum() panics unconditionally regardless of input
// length. The value is fixed by the algorithm, so there is nothing to compute.
const emptySHA1 = "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09"

func sha1T(data string) (string, bool, error) {
	if len(data) == 0 {
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
