// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/stretchr/testify/require"
)

func TestNoauditlogInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := noauditlog()
		r := &corazawaf.Rule{}
		require.NoError(t, a.Init(r, ""))

		require.False(t, r.Audit)
	})

	t.Run("unexpected arguments", func(t *testing.T) {
		a := noauditlog()
		err := a.Init(nil, "abc")
		require.Error(t, err)
		require.Equal(t, ErrUnexpectedArguments, err)
	})
}
