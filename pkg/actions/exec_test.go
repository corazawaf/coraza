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

package actions

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
	"os"
	"testing"
)

func TestExec(t *testing.T) {
	exec := &Exec{}
	waf := &engine.Waf{}
	waf.Init()
	r := &engine.Rule{}
	r.Init()
	tx := waf.NewTransaction()
	path, _ := os.Getwd()
	path += "/../../test/data/exec.lua"
	errors := exec.Init(r, path)
	if len(errors) > 0 {
		t.Error("Failed to load lua file")
	}
	exec.Evaluate(r, tx)

	id := tx.GetCollection("id").GetFirstString("")
	if id == "test" {
		t.Error("Failed to update transaction through exec LUA, shouldn't update ID")
	}

	body := tx.GetCollection("response_body").GetFirstString("")
	if body != "test" {
		t.Error("Failed to update transaction through exec LUA, got", body)
	}
}
