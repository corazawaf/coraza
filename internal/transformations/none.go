// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

func none(data string) (string, bool, error) {
	// This case is special and is hardcoded in the seclang parser
	return data, false, nil
}
