// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "errors"

// errMD5Disabled is returned on every evaluation of a rule using md5. md5 is not
// available in FIPS builds.
// The transformation stays registered so rules still load (allowing the CRS to load as-is);
// the engine logs a warning each time such a rule is actually triggered at runtime.
var errMD5Disabled = errors.New("md5 transformation is not available in FIPS builds")

func md5T(data string) (string, bool, error) {
	return data, false, errMD5Disabled
}
