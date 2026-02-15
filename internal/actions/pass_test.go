// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPassInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := pass()
		require.NoError(t, a.Init(nil, ""))
	})

	t.Run("unexpected arguments", func(t *testing.T) {
		a := nolog()
		err := a.Init(nil, "abc")
		require.Error(t, err)
		require.Equal(t, ErrUnexpectedArguments, err)
	})
}
