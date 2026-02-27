// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/stretchr/testify/require"
)

func TestMsgInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := msg()
		err := a.Init(nil, "")
		require.Error(t, err)
		require.Equal(t, ErrMissingArguments, err)
	})

	t.Run("with arguments", func(t *testing.T) {
		a := msg()
		r := &corazawaf.Rule{}
		require.NoError(t, a.Init(r, "test"))

		require.NotNil(t, r.Msg)
	})
}
