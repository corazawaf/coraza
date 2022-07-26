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

	"github.com/stretchr/testify/require"
)

func TestRG(t *testing.T) {
	r := NewRule()
	macroMsg, _ := NewMacro("test")
	r.Msg = *macroMsg
	r.ID = 1
	r.Tags = []string{
		"test",
	}

	rg := NewRuleGroup()
	err := rg.Add(r)

	require.NoError(t, err, "failed to add rule to rulegroup")
	require.Equal(t, 1, rg.Count(), "Failed to add rule to rulegroup")
	require.Len(t, rg.FindByMsg("test"), 1, "Failed to find rules by msg")
	require.Len(t, rg.FindByTag("test"), 1, "Failed to find rules by tag")

	rg.DeleteByID(1)
	require.Equal(t, 0, rg.Count(), "Failed to remove rule from rulegroup")
}
