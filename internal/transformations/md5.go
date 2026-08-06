// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"crypto/fips140"
	"crypto/md5"
	"errors"
	"io"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

// errMD5NotAvailableFIPS is returned on every evaluation of a rule using t:md5 when the binary
// runs in FIPS 140-3 mode (GODEBUG=fips140=on or =only), where MD5 is not an approved algorithm.
//
// The transformation stays registered so that rule sets referencing t:md5 still load. The error
// surfaces at evaluation time: the rule engine logs a warning and evaluates the operator against
// the untransformed argument, so the rule simply stops matching.
var errMD5NotAvailableFIPS = errors.New("md5 transformation is unavailable in FIPS 140-3 mode")

var emptyMD5 string

func md5T(data string) (string, bool, error) {
	if fips140.Enabled() {
		return data, false, errMD5NotAvailableFIPS
	}

	if len(data) == 0 {
		return emptyMD5, true, nil
	}

	h := md5.New()
	_, err := io.WriteString(h, data)
	if err != nil {
		return data, false, err
	}
	// The occurrence of an invariant transformation is so unlikely that we can assume the transformation returns a changed value
	// https://crypto.stackexchange.com/questions/68674/md5-existence-of-invariant-fixed-point
	return strings.WrapUnsafe(h.Sum(nil)), true, nil
}

func init() {
	if fips140.Enabled() {
		// md5.Sum panics under GODEBUG=fips140=only. emptyMD5 is left unset, md5T never reads it.
		return
	}
	buf := md5.Sum(nil)
	emptyMD5 = string(buf[:])
}
