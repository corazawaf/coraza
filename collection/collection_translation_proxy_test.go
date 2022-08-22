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

func TestCollectionTranslationProxy(t *testing.T) {
	c1 := NewMap(variables.ArgsPost)
	c2 := NewMap(variables.ArgsGet)
	proxy := NewTranslationProxy(variables.ArgsNames, c1, c2)

	c1.SetCS("key1", "key1", []string{"value1"})
	c1.Set("key2", []string{"value2"})
	c2.SetCS("key3", "Key3", []string{"value3"})

	if len(proxy.FindAll()) != 3 {
		t.Error("Error finding all")
	}
	if len(proxy.FindString("key3")) == 0 {
		t.Error("Error finding string")
	}
	if proxy.FindString("key1")[0].Value != "key1" {
		t.Error("Error value findstring key1")
	}
	if proxy.FindString("key3")[0].Value != "key3" {
		t.Error("Error value findstring key3")
	}
	if len(proxy.FindRegex(regexp.MustCompile("k.*"))) != 3 {
		t.Error("Error finding regex")
	}
}
