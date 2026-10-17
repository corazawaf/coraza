// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "path"

func normalisePath(data string) (string, bool, error) {
	leng := len(data)
	if leng < 1 {
		return data, false, nil
	}
	// SecLang paths use slash separators on every platform.
	clean := path.Clean(data)
	if clean == "." {
		return "", true, nil
	}
	// Keep a trailing separator as ModSecurity does, except for the root,
	// which path.Clean already returns as "/".
	if data[len(data)-1] == '/' && clean != "/" {
		result := clean + "/"
		return result, data != result, nil
	}
	return clean, data != clean, nil
}
