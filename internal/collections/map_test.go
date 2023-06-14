// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package collections

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestMap(t *testing.T) {
	c := NewMap(variables.ArgsPost)
	c.SetIndex("key", 1, "value")
	c.Set("key2", []string{"value2"})
	if c.Get("key")[0] != "value" {
		t.Error("Error setting index")
	}
	if len(c.FindAll()) == 0 {
		t.Error("Error finding all")
	}
	if len(c.FindString("a")) > 0 {
		t.Error("Error should not find string")
	}
	if l := len(c.FindRegex(regexp.MustCompile("k.*"))); l != 2 {
		t.Errorf("Error should find regex, got %d", l)
	}

	c.Add("key2", "value3")

	wantStr := `ARGS_POST:
    key: value
    key2: value2,value3
`

	if have := fmt.Sprint(c); have != wantStr {
		// Map order is not guaranteed, not pretty but checking twice is the simplest for now.
		wantStr = `ARGS_POST:
    key2: value2,value3
    key: value
`
		if have != wantStr {
			t.Errorf("String() = %q, want %q", have, wantStr)
		}
	}

	if c.Len() != len(c.data) {
		t.Fatal("The lengths are not equal.")
	}

}
