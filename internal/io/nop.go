// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package io

import "io"

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func NopCloser(w io.Writer) io.WriteCloser {
	return nopCloser{w}
}
