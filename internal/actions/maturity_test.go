// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v4/internal/corazawaf"
)

func TestMaturityInit(t *testing.T) {
	for _, test := range []struct {
		data             string
		expectedError    bool
		expectedMaturity int
	}{
		{"", true, 0},
		{"abc", true, 0},
		{"-10", true, 0},
		{"0", true, 0},
		{"5", false, 5},
		{"10", true, 0},
	} {
		a := maturity()
		r := &corazawaf.Rule{}
		err := a.Init(r, test.data)
		if test.expectedError {
			if err == nil {
				t.Errorf("expected error: %s", err.Error())
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}

			if want, have := test.expectedMaturity, r.Maturity_; want != have {
				t.Errorf("unexpected maturity value, want %d, have %d", want, have)
			}
		}
	}
}
