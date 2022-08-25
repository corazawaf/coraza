// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"crypto/sha1"
	"io"
)

func sha1T(data string) (string, error) {
	h := sha1.New()
	_, err := io.WriteString(h, data)
	if err != nil {
		return data, err
	}
	return string(h.Sum(nil)), nil
}
