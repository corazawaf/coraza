// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedirectInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := redirect()
		err := a.Init(nil, "")
		require.Error(t, err)
		require.Equal(t, ErrMissingArguments, err)
	})

	t.Run("passed arguments", func(t *testing.T) {
		a := redirect()
		require.NoError(t, a.Init(nil, "abc"))

		require.Equal(t, "abc", a.(*redirectFn).target)
	})
}
