// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasilibs

// Register registers the pm, rx, and detect_xss operators using WASI implementations
// instead of Go. Note that it does not register a WASI implementation of the detect_sqli
// operator which has not been found to outperform the Go implementation.
func Register() {
	RegisterPM()
	RegisterRX()
	RegisterXSS()
}
