// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import "testing"

func TestRedirectInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := redirect()
		if err := a.Init(nil, ""); err == nil || err != ErrMissingArguments {
			t.Error("expected error ErrMissingArguments")
		}
	})

	t.Run("passed arguments", func(t *testing.T) {
		a := redirect()
		if err := a.Init(nil, "abc"); err != nil {
			t.Error("unexpected error")
		}

		if want, have := "abc", a.(*redirectFn).target; want != have {
			t.Errorf("unexpected target, want %q, got %q", want, have)
		}
	})
}
