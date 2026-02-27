// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/stretchr/testify/require"
)

func TestVerInit(t *testing.T) {
	t.Run("passed arguments", func(t *testing.T) {
		a := ver()
		r := &corazawaf.Rule{}
		require.NoError(t, a.Init(r, "1.2.3"))

		require.Equal(t, "1.2.3", r.Version_)
	})

	t.Run("missing arguments", func(t *testing.T) {
		a := ver()
		err := a.Init(nil, "")
		require.Error(t, err)
		require.Equal(t, ErrMissingArguments, err)
	})
}
