// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package memoize

func Do(_ string, fn func() (interface{}, error)) (interface{}, error) {
	return fn()
}
