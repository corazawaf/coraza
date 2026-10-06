// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestAccuracyInit(t *testing.T) {
	for _, test := range []struct {
		data             string
		expectedError    bool
		expectedAccuracy int
	}{
		{"", true, 0},
		{"abc", true, 0},
		{"-10", true, 0},
		{"0", true, 0},
		{"5", false, 5},
		{"10", true, 0},
	} {
		a := accuracy()
		r := &corazawaf.Rule{}
		err := a.Init(r, test.data)
		if test.expectedError {
			if err == nil {
				t.Errorf("expected error")
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}

			if want, have := test.expectedAccuracy, r.Accuracy_; want != have {
				t.Errorf("unexpected accuracy value, want %d, have %d", want, have)
			}
		}
	}
}
