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
	"strings"
)

// Initializes a persistent collection and add the data to the standard collections engine.
type InitCol struct {
	Collection string
	Key        string
}

func (a *InitCol) Init(r *engine.Rule, data string) string {
	kv := strings.SplitN(data, "=", 2)
	a.Collection = kv[0]
	a.Key = kv[1]
	return ""
}

func (a *InitCol) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	pc := &engine.PersistentCollection{}
	pc.New(tx.WafInstance.PersistenceEngine, tx.WafInstance.WebAppId, a.Collection, tx.MacroExpansion(a.Key), 10000)
	col := tx.GetCollection(a.Collection)

	col.SetData(pc.GetData())
	tx.RegisterPersistentCollection(a.Collection, pc)
}

func (a *InitCol) GetType() int {
	return engine.ACTION_TYPE_NONDISRUPTIVE
}
