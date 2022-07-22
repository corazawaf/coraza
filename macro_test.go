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
)

func TestMacro(t *testing.T) {
	tx := makeTransaction(t)
	tx.GetCollection(variables.TX).Set("some", []string{"secretly"})
	macro, err := NewMacro("%{unique_id}")
	if err != nil {
		t.Error(err)
	}
	if macro.Expand(tx) != tx.ID {
		t.Errorf("%s != %s", macro.Expand(tx), tx.ID)
	}
	macro, err = NewMacro("some complex text %{tx.some} wrapped in macro")
	if err != nil {
		t.Error(err)
	}
	if macro.Expand(tx) != "some complex text secretly wrapped in macro" {
		t.Errorf("failed to expand macro, got %s\n%v", macro.Expand(tx), macro.tokens)
	}

	macro, err = NewMacro("some complex text %{tx.some} wrapped in macro %{tx.some}")
	if err != nil {
		t.Error(err)
		return
	}
	if !macro.IsExpandable() || len(macro.tokens) != 4 || macro.Expand(tx) != "some complex text secretly wrapped in macro secretly" {
		t.Errorf("failed to parse replacements %v", macro.tokens)
	}
}
