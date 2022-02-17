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

package actions

import (
	"strings"

	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types"
)

// Initializes a persistent collection and add the data to the standard collections coraza.
type initcolFn struct {
	collection string
	variable   byte
	key        string
}

func (a *initcolFn) Init(r *coraza.Rule, data string) error {
	kv := strings.SplitN(data, "=", 2)
	a.collection = kv[0]
	a.key = kv[1]
	a.variable = 0x0
	return nil
}

func (a *initcolFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// tx.Waf.Logger.Error("initcol was used but it's not supported", zap.Int("rule", r.Id))
	/*
		key := tx.MacroExpansion(a.key)
		data := tx.Waf.Persistence.Get(a.variable, key)
		if data == nil {
			ts := time.Now().UnixNano()
			tss := strconv.FormatInt(ts, 10)
			tsstimeout := strconv.FormatInt(ts+(int64(tx.Waf.CollectionTimeout)*1000), 10)
			data = map[string][]string{
				"CREATE_TIME":      {tss},
				"IS_NEW":           {"1"},
				"KEY":              {key},
				"LAST_UPDATE_TIME": {tss},
				"TIMEOUT":          {tsstimeout},
				"UPDATE_COUNTER":   {"0"},
				"UPDATE_RATE":      {"0"},
			}
		}
		tx.GetCollection(a.variable).SetData(data)
		tx.PersistentCollections[a.variable] = key
	*/
}

func (a *initcolFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func initcol() coraza.RuleAction {
	return &initcolFn{}
}

var (
	_ coraza.RuleAction = &initcolFn{}
	_ ruleActionWrapper = initcol
)
