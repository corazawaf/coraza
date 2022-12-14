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
package collection

import (
	"regexp"
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestCollectionMapCaseInsensitive(t *testing.T) {
	c := NewMap(variables.ArgsPost, false)
	c.Set("key", []string{"value2"})
	c.SetIndex("key", 0, "value")
	c.Add("keY2", "value3")
	if c.Get("key")[0] != "value" {
		t.Error("Error setting index")
	}
	if len(c.Find(NewQueryAll())) == 0 {
		t.Error("Error finding all")
	}
	if len(c.Find(NewQueryEquals("a"))) > 0 {
		t.Error("Error should not find string")
	}
	if len(c.Find(NewQueryEquals("key2"))) != 1 {
		t.Error("Error should find string")
	}
	if l := len(c.Find(NewQueryRegex(regexp.MustCompile("k.*")))); l != 2 {
		t.Errorf("Error should find regex, got %d", l)
	}
}

func TestCollectionMapCaseSensitive(t *testing.T) {
	c := NewMap(variables.RequestHeaders, true)
	c.Set("kEy", []string{"value2"})
	c.SetIndex("key2", 5, "value")
	c.Set("Keeey", []string{"value3"})
	if len(c.Find(NewQueryAll())) == 0 {
		t.Error("Error finding all")
	}
	if len(c.Find(NewQueryEquals("a"))) > 0 {
		t.Error("Error should not find string")
	}
	if len(c.Find(NewQueryEquals("kEy"))) != 1 {
		t.Error("Error should find string")
	}
	if len(c.Find(NewQueryEquals("key"))) != 0 {
		t.Error("Error should not find string")
	}
	if l := len(c.Find(NewQueryRegex(regexp.MustCompile("k.*")))); l != 2 {
		t.Errorf("Error should find regex, got %d", l)
	}
}
