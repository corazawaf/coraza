// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"path/filepath"
)

func normalisePath(data string) (string, error) {
	leng := len(data)
	if leng < 1 {
		return data, nil
	}
	clean := filepath.Clean(data)
	if clean == "." {
		return "", nil
	}
	if data[len(data)-1] == '/' {
		return clean + "/", nil
	}
	return clean, nil
}
