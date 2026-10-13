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
// runs in FIPS 140-3 mode (GODEBUG=fips140=on, =debug or =only).
//
// TODO: soften this to GODEBUG=fips140=only once Go 1.25 is no longer supported. Only that mode
// actually makes crypto/sha1 unusable (its checkSum() panics); fips140=on and fips140=debug
// leave it working. Distinguishing them needs crypto/fips140.Enforced(), which is Go 1.26+, so
// until the floor moves the stricter policy stands: any FIPS mode disables the transformation.
//
// Note that SHA-1 itself is approved under FIPS 180-4 and permitted for non-signature use until
// 2030 (NIST SP 800-131A), and t:sha1 here is a normalization/keying function rather than a
// security service, so this is Coraza policy rather than something FIPS 140-3 requires.
//
// The transformation stays registered so that rule sets referencing t:sha1 still load, including the
// CRS. The error surfaces at evaluation time instead: the rule engine logs a warning and keeps the
// untransformed argument. The rule is NOT
// skipped and the transformation chain is NOT aborted, so any subsequent transformation runs on the
// raw value and the operator is evaluated against the result. Review rules that depend on t:sha1
// before deploying in FIPS mode.
var errSHA1NotAvailableFIPS = errors.New("sha1 transformation is unavailable in FIPS 140-3 mode")

// The SHA-1 digest of an empty input, hardcoded rather than computed via sha1.Sum(nil): that call
// panics under GODEBUG=fips140=only, even lazily, since crypto/sha1's checkSum() panics
// unconditionally regardless of input length. The value is fixed by the algorithm, so there is
// nothing to compute.
const emptySHA1 = "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09"

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
