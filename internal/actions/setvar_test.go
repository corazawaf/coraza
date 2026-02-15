// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"bytes"
	"testing"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/stretchr/testify/require"
)

type md struct {
}

func (md) ID() int {
	return 0
}
func (md) ParentID() int {
	return 0
}
func (md) Status() int {
	return 0
}

func TestSetvarInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := setvar()
		err := a.Init(nil, "")
		require.Error(t, err)
		require.Equal(t, ErrMissingArguments, err)
	})
	t.Run("non-map variable", func(t *testing.T) {
		a := setvar()
		require.Error(t, a.Init(&md{}, "PATH_INFO=test"))
	})
	t.Run("TX set ok", func(t *testing.T) {
		a := setvar()
		require.NoError(t, a.Init(&md{}, "TX.some=test"))
	})
	t.Run("TX without key should fail", func(t *testing.T) {
		a := setvar()
		require.Error(t, a.Init(&md{}, "TX=test"))
	})
}

var invalidSyntaxAtoiError = "invalid syntax"
var warningKeyNotFoundInCollection = "key not found in collection"

func TestSetvarEvaluate(t *testing.T) {
	tests := []struct {
		name                     string
		init                     string
		init2                    string
		expectInvalidSyntaxError bool
		expectNewVarValue        string
	}{
		{
			name:                     "Numerical operation + with existing variable",
			init:                     "TX.var=5",
			init2:                    "TX.newvar=+%{tx.var}",
			expectInvalidSyntaxError: false,
			expectNewVarValue:        "5",
		},
		{
			name:                     "Numerical operation - with existing variable",
			init:                     "TX.var=5",
			init2:                    "TX.newvar=-%{tx.var}",
			expectInvalidSyntaxError: false,
			expectNewVarValue:        "-5",
		},
		{
			name:                     "Numerical operation - with existing negative variable",
			init:                     "TX.newvar=-5",
			init2:                    "TX.newvar=+5",
			expectInvalidSyntaxError: false,
			expectNewVarValue:        "0",
		},
		{
			name:                     "Numerical operation + with missing (or non-numerical) variable",
			init:                     "TX.newvar=+%{tx.missingvar}",
			expectInvalidSyntaxError: true,
		},
		{
			name:                     "Numerical operation - with missing (or non-numerical) variable",
			init:                     "TX.newvar=-%{tx.missingvar}",
			expectInvalidSyntaxError: true,
		},
		{
			name:                     "Non Numerical Operation - If the value starts with -",
			init:                     "TX.newvar=----expected_value",
			expectInvalidSyntaxError: false,
			expectNewVarValue:        "----expected_value",
		},
		{
			name:                     "Non Numerical Operation - If the value starts with +",
			init:                     "TX.newvar=+++expected_value",
			expectInvalidSyntaxError: false,
			expectNewVarValue:        "+++expected_value",
		},
	}

	for _, tt := range tests {
		logsBuf := &bytes.Buffer{}

		logger := debuglog.Default().WithLevel(debuglog.LevelWarn).WithOutput(logsBuf)

		t.Run(tt.name, func(t *testing.T) {
			defer logsBuf.Reset()
			a := setvar()
			metadata := &md{}
			require.NoError(t, a.Init(metadata, tt.init), "unexpected error during setvar init")

			waf := corazawaf.NewWAF()
			waf.Logger = logger

			tx := waf.NewTransaction()
			a.Evaluate(metadata, tx)

			if tt.expectInvalidSyntaxError {
				t.Log(logsBuf.String())
				require.NotZero(t, logsBuf.Len(), "expected logs")

				require.Contains(t, logsBuf.String(), invalidSyntaxAtoiError)

				require.Contains(t, logsBuf.String(), warningKeyNotFoundInCollection)
			} else {
				require.Zero(t, logsBuf.Len())
			}

			if tt.init2 != "" {
				require.NoError(t, a.Init(metadata, tt.init2), "unexpected error during setvar init")
				a.Evaluate(metadata, tx)
				if !tt.expectInvalidSyntaxError {
					require.Zero(t, logsBuf.Len())
				}
			}
			if tt.expectNewVarValue != "" {
				checkCollectionValue(t, a.(*setvarFn), tx, "newvar", tt.expectNewVarValue)
			}
		})
	}
}

func checkCollectionValue(t *testing.T, a *setvarFn, tx plugintypes.TransactionState, key string, expected string) {
	t.Helper()
	var col collection.Map
	if c, ok := tx.Collection(a.collection).(collection.Map); !ok {
		t.Fatal("collection in setvar is not a map")
		return
	} else {
		col = c
	}
	require.NotNil(t, col, "collection in setvar is nil")
	require.Equal(t, expected, col.Get(key)[0])
}
