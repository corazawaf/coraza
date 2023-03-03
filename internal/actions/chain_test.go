// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestChainInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := chain()
		r := &corazawaf.Rule{}
		if err := a.Init(r, ""); err != nil {
			t.Error(err)
		}

		if want, have := true, r.HasChain; want != have {
			t.Errorf("expected action %t, got %t", want, have)
		}
	})

	t.Run("unexpected arguments", func(t *testing.T) {
		a := chain()
		if err := a.Init(nil, "abc"); err == nil || err != ErrUnexpectedArguments {
			t.Error("expected error ErrUnexpectedArguments")
		}
	})
}
