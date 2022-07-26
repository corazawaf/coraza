// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package coraza

import (
	"testing"

	"github.com/corazawaf/coraza/v2/types/variables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleNegativeVariables(t *testing.T) {
	rule := NewRule()

	err := rule.AddVariable(variables.Args, "", false)
	require.NoError(t, err)
	assert.Equal(t, variables.Args, rule.variables[0].Variable, "Variable not added")
	assert.Nil(t, rule.variables[0].KeyRx, "invalid key type for variable")

	err = rule.AddVariableNegation(variables.Args, "test")
	require.NoError(t, err)

	require.Len(t, rule.variables[0].Exceptions, 1)
	assert.Equal(t, "test", rule.variables[0].Exceptions[0].KeyStr)

	err = rule.AddVariable(variables.Args, "/test.*/", false)
	require.NoError(t, err)

	require.NotNil(t, rule.variables[1].KeyRx)
	assert.Equal(t, "test.*", rule.variables[1].KeyRx.String())
}

func TestVariableKeysAreCaseInsensitive(t *testing.T) {
	rule := NewRule()

	err := rule.AddVariable(variables.Args, "Som3ThinG", false)
	require.NoError(t, err)
	assert.Equal(t, "som3thing", rule.variables[0].KeyStr, "variable key is not case insensitive")
}

func TestVariablesRxAreCaseSensitive(t *testing.T) {
	rule := NewRule()

	err := rule.AddVariable(variables.Args, "/Som3ThinG/", false)
	require.NoError(t, err)

	assert.Equal(t, "Som3ThinG", rule.variables[0].KeyRx.String(), "variable key is not case insensitive")
}
