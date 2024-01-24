// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v4/internal/corazawaf"
)

func TestIdInit(t *testing.T) {
	for _, test := range []struct {
		data         string
		expectedID   int
		expectsError bool
	}{
		{"", 0, true},
		{"x", 0, true},
		{"0", 0, true},
		{"-10", 0, true},
		{"10", 10, false},
	} {
		r := &corazawaf.Rule{}
		t.Run(test.data, func(t *testing.T) {
			a := id()
			err := a.Init(r, test.data)

			if test.expectsError && err == nil {
				t.Error("expected error")
			} else if !test.expectsError && err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}

			if want, have := test.expectedID, r.ID_; want != have {
				t.Errorf("unexpected id, want: %d, have: %d", want, have)
			}
		})
	}
}
