// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v4/internal/corazawaf"
)

func TestCaptureInit(t *testing.T) {
	t.Run("passed arguments", func(t *testing.T) {
		a := capture()
		r := &corazawaf.Rule{}
		if err := a.Init(r, ""); err != nil {
			t.Error(err)
		}
		if want, have := true, r.Capture; want != have {
			t.Errorf("expected action %t, got %t", want, have)
		}
	})

	t.Run("no arguments", func(t *testing.T) {
		a := capture()
		if err := a.Init(nil, "abc"); err == nil || err != ErrUnexpectedArguments {
			t.Error("expected error ErrUnexpectedArguments")
		}
	})
}
