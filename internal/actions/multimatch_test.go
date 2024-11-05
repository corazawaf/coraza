// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestMultiMatchInit(t *testing.T) {
	t.Run("with arguments", func(t *testing.T) {
		a := multimatch()
		if err := a.Init(nil, "abc"); err == nil || err != ErrUnexpectedArguments {
			t.Error("expected error ErrUnexpectedArguments")
		}
	})

	t.Run("no arguments", func(t *testing.T) {
		a := multimatch()
		r := &corazawaf.Rule{}
		if err := a.Init(r, ""); err != nil {
			t.Error(err)
		}

		if !r.MultiMatch {
			t.Errorf("expected multimatch to be true")
		}
	})
}
