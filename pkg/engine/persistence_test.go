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

package engine

import (
	"github.com/jptosso/coraza-waf/pkg/engine/persistence"
	"testing"
)

var engine PersistenceEngine
var col *PersistentCollection

func TestInitialization(t *testing.T) {
	engine = &persistence.MemoryEngine{}
	engine.Init("")
	col = &PersistentCollection{}
	col.Init(engine, "testapp", "SESSION", "127.0.0.1")

	test := col.GetData()
	test["TEST"] = []string{"123"}
	col.SetData(test)
	col.Save()

	// we reset the persistent collection
	col = &PersistentCollection{}
	col.Init(engine, "testapp", "SESSION", "127.0.0.1")

	data := col.GetData()
	if len(data) == 0 {
		t.Error("Failed to retrieve persistent collection")
	}

	if len(data["TEST"]) != 1 {
		t.Error("Failed to retrieve persistent collection")
	}

	if data["TEST"][0] != "123" {
		t.Error("Failed to retrieve persistent collection")
	}

	if data["IS_NEW"][0] != "1" {
		t.Error("Failed to retrieve persistent collection")
	}
}
