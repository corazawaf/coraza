// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"strings"
	"testing"
)

func TestPhaseInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := phase()
		if err := a.Init(nil, ""); err == nil || err != ErrMissingArguments {
			t.Error("expected error ErrMissingArguments")
		}
	})

	t.Run("unknown phase", func(t *testing.T) {
		a := phase()
		if err := a.Init(nil, "connect"); err == nil || strings.Contains(err.Error(), "unknown phase") {
			t.Error("expected error for unknown phase")
		}
	})
}
