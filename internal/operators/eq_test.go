// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestEq(t *testing.T) {
	eq, _ := newEq(plugintypes.OperatorOptions{
		Arguments: "1",
	})

	testCases := map[string]bool{
		"1":   true,
		"01":  true,
		"1.0": false,
	}

	for value, want := range testCases {
		t.Run(value, func(t *testing.T) {
			if have := eq.Evaluate(nil, value); want != have {
				t.Errorf("unexpected result: want %v, have %v", want, have)
			}
		})
	}
}
