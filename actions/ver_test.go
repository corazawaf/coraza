// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestVerInit(t *testing.T) {
	t.Run("passed arguments", func(t *testing.T) {
		a := ver()
		r := &corazawaf.Rule{}
		if err := a.Init(r, "1.2.3"); err != nil {
			t.Error(err)
		}

		if want, have := "1.2.3", r.Version_; want != have {
			t.Errorf("expected version %s, got %s", want, have)
		}
	})

	t.Run("missing arguments", func(t *testing.T) {
		a := ver()
		if err := a.Init(nil, ""); err == nil || err != ErrMissingArguments {
			t.Error("expected error ErrMissingArguments")
		}
	})
}
