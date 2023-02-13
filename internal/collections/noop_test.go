// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"testing"
)

func TestNoop(t *testing.T) {
	c := Noop

	if c.Name() != "" {
		t.Error("noop name failed")
	}
	assertValuesMatch(t, c.FindAll(), "")
}
