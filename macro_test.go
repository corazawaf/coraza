// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"testing"
)

func TestMacro(t *testing.T) {
	tx := makeTransaction(t)
	tx.Variables.TX.Set("some", []string{"secretly"})

	testCases := []struct {
		name              string
		macro             string
		IsExpandable      bool
		expectedExpansion string
		numTokens         int
	}{
		{
			name:              "empty",
			macro:             "",
			expectedExpansion: "",
			numTokens:         0,
		},
		{
			name:              "unexisting",
			macro:             "%{unknown}",
			expectedExpansion: "",
			numTokens:         1,
		},
		{
			name:              "alone",
			macro:             "%{unique_id}",
			expectedExpansion: tx.ID,
			numTokens:         1,
		},
		{
			name:              "within a text",
			macro:             "some complex text %{tx.some} wrapped in macro",
			expectedExpansion: "some complex text secretly wrapped in macro",
			IsExpandable:      true,
			numTokens:         3,
		},
		{
			name:              "repeated inside a text",
			macro:             "some complex text %{tx.some} wrapped in macro %{tx.some}",
			expectedExpansion: "some complex text secretly wrapped in macro secretly",
			IsExpandable:      true,
			numTokens:         4,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			macro, err := NewMacro(testCase.macro)
			if err != nil {
				t.Error(err)
			}

			if want, have := testCase.IsExpandable, macro.IsExpandable(); want != have {
				t.Errorf("unexpected expandability, want %t, have %t", want, have)
			}

			if want, have := testCase.numTokens, len(macro.tokens); want != have {
				t.Errorf("unexpected number of tokens, want %d, have %d", want, have)
			}

			if want, have := testCase.expectedExpansion, macro.Expand(tx); want != have {
				t.Errorf("unexpected expansion, want %q, have %q", want, have)
			}
		})
	}
}
