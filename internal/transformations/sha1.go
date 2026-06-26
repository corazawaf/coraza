// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "errors"

// errSHA1Disabled is returned on every evaluation of a rule using sha1.
// sha1 is not available in FIPS builds.
// The transformation stays registered so rules still load (allowing the CRS to load as-is);
// the engine logs a warning each time such a rule is actually triggered at runtime.
var errSHA1Disabled = errors.New("sha1 transformation is not available in FIPS builds")

func sha1T(data string) (string, bool, error) {
	return data, false, errSHA1Disabled
}
