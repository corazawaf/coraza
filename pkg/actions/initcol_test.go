// Copyright 2020 Juan Pablo Tosso
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
	"testing"
)

func TestInitcol(t *testing.T) {
	w := engine.NewWaf()
	tx := w.NewTransaction()
	r := &engine.Rule{}
	r.Init()

	ic := InitCol{}
	if ic.Init(r, "session=test") != "" {
		t.Error("Failed to initialize persistent collection")
	}
	ic.Evaluate(r, tx)
	if len(tx.PersistentCollections) == 0 {
		t.Error("Failed to initialize persistent collection")
	}
}
