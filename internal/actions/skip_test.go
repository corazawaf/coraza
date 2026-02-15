// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSkipInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := skip()
		err := a.Init(nil, "")
		require.Error(t, err)
		require.Equal(t, ErrMissingArguments, err)
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
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				require.Equal(t, test.expectedData, a.(*skipFn).data)
			}
		}
	})
}
