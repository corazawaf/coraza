// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"
)

func TestSkipInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := skip()
		if err := a.Init(nil, ""); err == nil || err != ErrMissingArguments {
			t.Error("expected error ErrMissingArguments")
		}
	})

	t.Run("with arguments", func(t *testing.T) {
		for _, test := range []struct {
			data          string
			expectedError bool
			expectedData  int
		}{
			{"abc", true, 0},
			{"-10", true, 0},
			{"0", true, 0},
			{"5", false, 5},
		} {
			a := skip()
			err := a.Init(nil, test.data)
			if test.expectedError {
				if err == nil {
					t.Errorf("expected error: %s", err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err.Error())
				}

				if want, have := test.expectedData, a.(*skipFn).data; want != have {
					t.Errorf("unexpected maturity value, want %d, have %d", want, have)
				}
			}
		}
	})
}
