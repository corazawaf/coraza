// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/redwanghb/coraza/v3/internal/corazawaf"
)

func TestNologInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := nolog()
		r := &corazawaf.Rule{}
		if err := a.Init(r, ""); err != nil {
			t.Error(err)
		}

		if r.Audit {
			t.Error("unexpected audit value")
		}

		if r.Log {
			t.Error("unexpected log value")
		}
	})

	t.Run("unexpected arguments", func(t *testing.T) {
		a := nolog()
		if err := a.Init(nil, "abc"); err == nil || err != ErrUnexpectedArguments {
			t.Error("expected error ErrUnexpectedArguments")
		}
	})
}
