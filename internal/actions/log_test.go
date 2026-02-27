// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/stretchr/testify/require"
)

func TestLogInit(t *testing.T) {
	a := log()
	r := &corazawaf.Rule{}
	err := a.Init(r, "")
	require.NoError(t, err)

	require.True(t, r.Log)

	require.True(t, r.Audit)
}
