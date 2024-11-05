// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"
)

func TestPassInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := pass()
		if err := a.Init(nil, ""); err != nil {
			t.Error(err)
		}
	})

	t.Run("unexpected arguments", func(t *testing.T) {
		a := nolog()
		if err := a.Init(nil, "abc"); err == nil || err != ErrUnexpectedArguments {
			t.Error("expected error ErrUnexpectedArguments")
		}
	})
}
