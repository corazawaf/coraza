// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"crypto/md5"
	"io"
	"sync"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

var (
	emptyMD5     string
	emptyMD5Once sync.Once
)

func md5T(data string) (string, bool, error) {
	if len(data) == 0 {
		// Computed lazily to avoid calling MD5 in an init, which panics under GODEBUG=fips140=only.
		emptyMD5Once.Do(func() {
			sum := md5.Sum(nil)
			emptyMD5 = string(sum[:])
		})
		return emptyMD5, true, nil
	}

	h := md5.New()
	_, err := io.WriteString(h, data)
	if err != nil {
		return data, false, err
	}
	// The occurrence of an invariant transformation is so unlikely that we can assume the transformation returns a changed value
	// https://crypto.stackexchange.com/questions/68674/md5-existence-of-invariant-fixed-point
	return strings.WrapUnsafe(h.Sum(nil)), true, nil
}
