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
	"strconv"
	"strings"
)

type Setvar struct {
	Key        string
	Value      string
	Collection string
}

//this action win run even if rule is not triggered.!
func (a *Setvar) Init(r *engine.Rule, data string) string {
	//sample: tx.%{rule.id}-WEB_ATTACK/SQL_INJECTION-%{matched_var_name}=%{tx.0}
	if data[0] == '\'' {
		data = strings.Trim(data, "'")
	}
	//kv[0] = tx.%{rule.id}-WEB_ATTACK/SQL_INJECTION-%{matched_var_name}
	//kv[1] = %{tx.0}
	kv := strings.SplitN(data, "=", 2)
	kv[0] = strings.ToLower(kv[0])
	//spl[0] = tx
	//spl[1] = %{rule.id}-WEB_ATTACK/SQL_INJECTION-%{matched_var_name}
	spl := strings.SplitN(kv[0], ".", 2)
	//allowed := []string{"tx", "ip", "session"}
	a.Collection = spl[0]
	a.Key = strings.ToLower(spl[1])
	a.Value = kv[1]
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

	if a.Key[0] == '!' {
		collection.Remove(a.Key[1:])
	} else {
		res := collection.Get(a.Key)
		if len(res) == 0 {
			collection.Set(tx.MacroExpansion(a.Key), []string{"0"})
			res = []string{"0"}
		}
		if a.Value[0] == '+' {
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
}
