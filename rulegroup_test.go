// Copyright 2021 Juan Pablo Tosso
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
)

func TestRG(t *testing.T) {
	r := NewRule()
	r.Msg = "test"
	r.Id = 1
	r.Tags = []string{
		"test",
	}

	rg := NewRuleGroup()
	rg.Add(r)

	if rg.Count() != 1 {
		t.Error("Failed to add rule to rulegroup")
	}

	if len(rg.FindByMsg("test")) != 1 {
		t.Error("Failed to find rules by msg")
	}

	if len(rg.FindByTag("test")) != 1 {
		t.Error("Failed to find rules by tag")
	}

	rg.DeleteById(1)
	if rg.Count() != 0 {
		t.Error("Failed to remove rule from rulegroup")
	}
}
