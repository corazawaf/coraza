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
package collection

import (
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestCollectionSizeProxy(t *testing.T) {
	c1 := NewCollectionMap(variables.ArgsPost)
	c2 := NewCollectionMap(variables.ArgsGet)
	proxy := NewCollectionSizeProxy(variables.Args, c1, c2)

	c1.Set("key1", []string{"value1", "value2"})
	c1.Set("key2", []string{"value2"})
	c2.Set("key3", []string{"value3"})
	if proxy.Size() != 24 {
		t.Errorf("Error finding size for size proxy, got %d", proxy.Size())
	}

}
