// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/redwanghb/coraza/v3/internal/corazawaf"
)

func TestMsgInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := msg()
		if err := a.Init(nil, ""); err == nil || err != ErrMissingArguments {
			t.Error("expected error ErrMissingArguments")
		}
	})

	t.Run("with arguments", func(t *testing.T) {
		a := msg()
		r := &corazawaf.Rule{}
		if err := a.Init(r, "test"); err != nil {
			t.Error(err)
		}

		if r.Msg == nil {
			t.Error("expected msg to be set")
		}
	})
}
