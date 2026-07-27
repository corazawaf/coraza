// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package macro

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestNewMacro(t *testing.T) {
	_, err := NewMacro("")
	require.Error(t, err)

	_, err = NewMacro("some string")
	require.NoError(t, err)

	_, err = NewMacro("%{}")
	require.Error(t, err)
}

func TestCompile(t *testing.T) {
	t.Run("empty data", func(t *testing.T) {
		m := &macro{}
		err := m.compile("")
		require.EqualError(t, err, "empty macro")
	})

	t.Run("single percent sign", func(t *testing.T) {
		m := &macro{}
		err := m.compile("%")
		require.NoError(t, err)
	})

	t.Run("empty braces", func(t *testing.T) {
		m := &macro{}
		err := m.compile("%{}")
		require.Error(t, err)
	})

	t.Run("missing key", func(t *testing.T) {
		m := &macro{}
		err := m.compile("%{tx.}")
		require.Error(t, err)
	})

	t.Run("missing collection", func(t *testing.T) {
		m := &macro{}
		err := m.compile("%{.key}")
		require.Error(t, err)
	})

	t.Run("malformed macros", func(t *testing.T) {
		for _, test := range []string{
			"%{tx.count", "%{{tx.count}", "%{{tx.{count}", "something %{tx.count",
			"%{ARG_NAMES:/exec/", // Wildcard variable names are not supported
		} {
			t.Run(test, func(t *testing.T) {
				m := &macro{}
				err := m.compile(test)
				require.Error(t, err)

				expectedErr := "malformed variable"
				require.ErrorContains(t, err, expectedErr)
			})
		}
	})

	t.Run("unknown variable", func(t *testing.T) {
		m := &macro{}

		err := m.compile("%{unknown_variable.x}")
		require.Error(t, err)

		expectedErr := "unknown variable"
		require.ErrorContains(t, err, expectedErr)
	})

	t.Run("unknown key", func(t *testing.T) {
		m := &macro{}

		err := m.compile("%{tx.missing_key}")
		require.NoError(t, err)

		require.Equal(t, 1, len(m.tokens))

		expectedMacro := macroToken{"tx.missing_key", variables.TX, "missing_key"}
		require.Equal(t, expectedMacro, m.tokens[0])
	})

	t.Run("valid macro", func(t *testing.T) {
		type testCase struct {
			input         string
			expectedMacro macroToken
		}
		for _, tc := range []testCase{
			{"%{tx.count}", macroToken{"tx.count", variables.TX, "count"}},
			{"%{ARGS.exec}", macroToken{"ARGS.exec", variables.Args, "exec"}},
			{"%{ARGS_GET.db[]}", macroToken{"ARGS_GET.db[]", variables.ArgsGet, "db[]"}},
		} {
			m := &macro{}
			err := m.compile(tc.input)
			require.NoError(t, err)

			require.Equal(t, 1, len(m.tokens))

			require.Equal(t, tc.expectedMacro, m.tokens[0])
		}
	})

	t.Run("multi variable", func(t *testing.T) {
		m := &macro{}
		err := m.compile("%{tx.id} got %{tx.count} in this transaction and as zero %{tx.0}")
		require.NoError(t, err)

		require.Equal(t, 5, len(m.tokens))

		expectedMacro0 := macroToken{"tx.id", variables.TX, "id"}
		require.Equal(t, expectedMacro0, m.tokens[0])

		expectedMacro1 := macroToken{" got ", variables.Unknown, ""}
		require.Equal(t, expectedMacro1, m.tokens[1])

		expectedMacro2 := macroToken{"tx.count", variables.TX, "count"}
		require.Equal(t, expectedMacro2, m.tokens[2])

		expectedMacro3 := macroToken{" in this transaction and as zero ", variables.Unknown, ""}
		require.Equal(t, expectedMacro3, m.tokens[3])

		expectedMacro4 := macroToken{"tx.0", variables.TX, "0"}
		require.Equal(t, expectedMacro4, m.tokens[4])
	})
}

func TestExpand(t *testing.T) {
	t.Run("unknown variable", func(t *testing.T) {
		m := &macro{
			tokens: []macroToken{
				{"text", variables.Unknown, ""},
			},
		}

		require.Equal(t, "text", m.Expand(nil))
	})
}
