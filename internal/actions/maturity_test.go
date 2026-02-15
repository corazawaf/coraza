// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/stretchr/testify/require"
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
			require.Error(t, err)
		} else {
			require.NoError(t, err)

			require.Equal(t, test.expectedMaturity, r.Maturity_)
		}
	}
}
