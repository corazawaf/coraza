// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import "testing"

func TestSetvarInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := setvar()
		if err := a.Init(nil, ""); err == nil || err != ErrMissingArguments {
			t.Error("expected error ErrMissingArguments")
		}
	})
}
