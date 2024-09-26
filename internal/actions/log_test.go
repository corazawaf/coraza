// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/redwanghb/coraza/v3/internal/corazawaf"
)

func TestLogInit(t *testing.T) {
	a := log()
	r := &corazawaf.Rule{}
	err := a.Init(r, "")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	if want, have := true, r.Log; want != have {
		t.Errorf("unexpected log value, want %t, have %t", want, have)
	}

	if want, have := true, r.Audit; want != have {
		t.Errorf("unexpected audit value, want %t, have %t", want, have)
	}
}
