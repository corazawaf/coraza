// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !memoize_builders

package memoize

func Do(_ string, fn func() (interface{}, error)) (interface{}, error) {
	return fn()
}
