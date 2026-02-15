// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/stretchr/testify/require"
)

func TestCaptureInit(t *testing.T) {
	t.Run("passed arguments", func(t *testing.T) {
		a := capture()
		r := &corazawaf.Rule{}
		require.NoError(t, a.Init(r, ""))
		require.True(t, r.Capture)
	})

	t.Run("no arguments", func(t *testing.T) {
		a := capture()
		err := a.Init(nil, "abc")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrUnexpectedArguments)
	})
}
