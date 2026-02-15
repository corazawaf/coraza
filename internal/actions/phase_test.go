// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPhaseInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := phase()
		err := a.Init(nil, "")
		require.Error(t, err)
		require.Equal(t, ErrMissingArguments, err)
	})

	t.Run("unknown phase", func(t *testing.T) {
		a := phase()
		err := a.Init(nil, "connect")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid phase")
	})
}
