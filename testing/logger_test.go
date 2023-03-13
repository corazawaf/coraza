// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	"testing"
)

type testLogOutput struct {
	t *testing.T
}

func (l testLogOutput) Write(p []byte) (int, error) {
	l.t.Log(string(p))
	return len(p), nil
}
