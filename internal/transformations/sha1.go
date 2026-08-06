// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"crypto/fips140"
	"crypto/sha1"
	"errors"
	"io"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

// errSHA1NotAvailableFIPS is returned on every evaluation of a rule using t:sha1 when the binary
// runs in FIPS 140-3 mode (GODEBUG=fips140=on or =only), where SHA-1 is not an approved algorithm.
//
// The transformation stays registered so that rule sets referencing t:sha1 still load, including the
// CRS. The error surfaces at evaluation time: the rule engine logs a warning and evaluates the operator
// against the untransformed argument, so the rule simply stops matching.
var errSHA1NotAvailableFIPS = errors.New("sha1 transformation is unavailable in FIPS 140-3 mode")

var emptySHA1 string

func sha1T(data string) (string, bool, error) {
	if fips140.Enabled() {
		return data, false, errSHA1NotAvailableFIPS
	}

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

func init() {
	if fips140.Enabled() {
		// sha1.Sum panics under GODEBUG=fips140=only. emptySHA1 is left unset, sha1T never reads it.
		return
	}
	buf := sha1.Sum(nil)
	emptySHA1 = string(buf[:])
}
