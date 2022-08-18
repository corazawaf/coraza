// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"crypto/md5"
	"io"
)

func md5T(data string) (string, error) {
	h := md5.New()
	_, err := io.WriteString(h, data)
	if err != nil {
		return data, err
	}
	return string(h.Sum(nil)), nil
}
