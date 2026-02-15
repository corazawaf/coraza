// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazatypes"
	"github.com/stretchr/testify/require"
)

func TestAllowInit(t *testing.T) {
	for _, test := range []struct {
		data              string
		expectedAllowType corazatypes.AllowType
	}{
		{"", corazatypes.AllowTypeAll},
		{"phase", corazatypes.AllowTypePhase},
		{"request", corazatypes.AllowTypeRequest},
	} {
		t.Run(test.data, func(t *testing.T) {
			a := allow()
			require.NoError(t, a.Init(nil, test.data))

			require.Equal(t, test.expectedAllowType, a.(*allowFn).allow)
		})
	}

	t.Run("invalid", func(t *testing.T) {
		require.Error(t, allow().Init(nil, "response"))
	})
}
