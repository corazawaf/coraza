// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"crypto/md5"
	"github.com/corazawaf/coraza/v3/internal/strings"
	"io"
)

var emptyMD5 string

func md5T(data string) (string, error) {
	if len(data) == 0 {
		return emptyMD5, nil
	}

	h := md5.New()
	_, err := io.WriteString(h, data)
	if err != nil {
		return data, err
	}
	return strings.WrapUnsafe(h.Sum(nil)), nil
}

func init() {
	buf := md5.Sum(nil)
	emptyMD5 = string(buf[:])
}
