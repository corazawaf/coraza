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
	"regexp"
	"testing"

	"github.com/jptosso/coraza-waf/v2/types/variables"
)

func TestLocalCollection(t *testing.T) {
}

func TestLocalCollectionMatchData(t *testing.T) {
	lc := NewCollection(variables.Args)
	lc.Set("test2", []string{"test3"})
	lc.Set("other4", []string{"test"})
	if l := len(lc.FindRegex(regexp.MustCompile("test.*"))); l != 1 {
		t.Errorf("failed to find regex, got %d", l)
	}
	if l := len(lc.FindString("other4")); l != 1 {
		t.Errorf("failed to find string, got %d", l)
	}
}

func TestAddUnique(t *testing.T) {
	col := NewCollection(variables.Args)
	col.AddUnique("test", "test2")
	col.AddUnique("test", "test2")
	if len(col.data["test"]) != 1 {
		t.Error("Failed to add unique")
	}
	if col.data["test"][0] != "test2" {
		t.Error("Failed to add unique")
	}
}
