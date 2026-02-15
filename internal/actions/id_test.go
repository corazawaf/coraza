// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/stretchr/testify/require"
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

			if test.expectsError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, test.expectedID, r.ID_)
		})
	}
}
