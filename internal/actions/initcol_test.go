// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitcolInit(t *testing.T) {
	t.Run("invalid argument", func(t *testing.T) {
		initcol := initcol()
		err := initcol.Init(nil, "foo")
		require.Error(t, err)
	})

	t.Run("passing argument", func(t *testing.T) {
		initcol := initcol()
		err := initcol.Init(nil, "foo=bar")
		require.NoError(t, err)
	})
}
