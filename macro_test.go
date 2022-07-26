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
	"github.com/stretchr/testify/require"
)

func TestMacro(t *testing.T) {
	tx := makeTransaction(t)
	tx.GetCollection(variables.TX).Set("some", []string{"secretly"})
	macro, err := NewMacro("%{unique_id}")
	require.NoError(t, err)
	require.Equal(t, tx.ID, macro.Expand(tx))

	macro, err = NewMacro("some complex text %{tx.some} wrapped in macro")
	require.NoError(t, err)
	require.Equal(t, "some complex text secretly wrapped in macro", macro.Expand(tx))

	macro, err = NewMacro("some complex text %{tx.some} wrapped in macro %{tx.some}")
	require.NoError(t, err)
	require.True(t, macro.IsExpandable())
	require.Len(t, macro.tokens, 4)
	require.Equal(t, "some complex text secretly wrapped in macro secretly", macro.Expand(tx))
}
