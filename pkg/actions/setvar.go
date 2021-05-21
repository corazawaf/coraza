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
	"strconv"
	"strings"
)

type Setvar struct {
	Key        string
	Value      string
	Collection string
	IsRemove   bool
}

//this action win run even if rule is not triggered.!
func (a *Setvar) Init(r *engine.Rule, data string) string {
	if data == "" {
		return "setvar requires arguments"
	}

	if data[0] == '!' {
		a.IsRemove = true
		data = data[1:]
	}

	spl := strings.SplitN(data, "=", 2)

	splcol := strings.SplitN(spl[0], ".", 2)
	a.Collection = splcol[0]
	if len(splcol) == 2 {
		a.Key = splcol[1]
	}
	if len(spl) == 2 {
		a.Value = spl[1]
	}
	return ""
}

func (a *Setvar) Evaluate(r *engine.Rule, tx *engine.Transaction) {
	key := tx.MacroExpansion(a.Key)
	value := tx.MacroExpansion(a.Value)
	a.evaluateTxCollection(r, tx, key, value)
}

func (a *Setvar) GetType() int {
	return engine.ACTION_TYPE_NONDISRUPTIVE
}

func (a *Setvar) evaluateTxCollection(r *engine.Rule, tx *engine.Transaction, key string, value string) {
	collection := tx.GetCollection(a.Collection)
	if collection == nil {
		//fmt.Println("Invalid Collection " + a.Collection) LOG error?
		return
	}

	if a.IsRemove {
		collection.Remove(a.Key)
		return
	}
	res := collection.Get(a.Key)
	if len(res) == 0 {
		collection.Set(tx.MacroExpansion(a.Key), []string{"0"})
		res = []string{"0"}
	}
	if len(a.Value) == 0 {
		collection.Set(tx.MacroExpansion(a.Key), []string{""})
	} else if a.Value[0] == '+' {
		me, _ := strconv.Atoi(tx.MacroExpansion(a.Value[1:]))
		txv, err := strconv.Atoi(res[0])
		if err != nil {
			return
		}
		collection.Set(tx.MacroExpansion(a.Key), []string{strconv.Itoa(me + txv)})
	} else if a.Value[0] == '-' {
		me, _ := strconv.Atoi(tx.MacroExpansion(a.Value[1:]))
		txv, err := strconv.Atoi(res[0])
		if err != nil {
			return
		}
		collection.Set(tx.MacroExpansion(a.Key), []string{strconv.Itoa(txv - me)})
	} else {
		collection.Set(tx.MacroExpansion(a.Key), []string{tx.MacroExpansion(a.Value)})
	}
}
