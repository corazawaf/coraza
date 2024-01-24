// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v4/internal/corazawaf"
)

func TestNoauditlogInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := noauditlog()
		r := &corazawaf.Rule{}
		if err := a.Init(r, ""); err != nil {
			t.Error(err)
		}

		if r.Audit {
			t.Error("unexpected audit value")
		}
	})

	t.Run("unexpected arguments", func(t *testing.T) {
		a := noauditlog()
		if err := a.Init(nil, "abc"); err == nil || err != ErrUnexpectedArguments {
			t.Error("expected error ErrUnexpectedArguments")
		}
	})
}
