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
	"fmt"
	"strconv"
	"strings"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types"
	"github.com/jptosso/coraza-waf/v2/types/variables"
)

type setvarFn struct {
	key        string
	value      string
	collection variables.RuleVariable
	isRemove   bool
}

func (a *setvarFn) Init(r *coraza.Rule, data string) error {
	if data == "" {
		return fmt.Errorf("setvar requires arguments")
	}

	if data[0] == '!' {
		a.isRemove = true
		data = data[1:]
	}

	var err error
	spl := strings.SplitN(data, "=", 2)

	splcol := strings.SplitN(spl[0], ".", 2)
	a.collection, err = variables.ParseVariable(splcol[0])
	if err != nil {
		return err
	}
	if len(splcol) == 2 {
		a.key = splcol[1]
	}
	if len(spl) == 2 {
		a.value = spl[1]
	}
	return nil
}

func (a *setvarFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	key := tx.MacroExpansion(a.key)
	value := tx.MacroExpansion(a.value)
	a.evaluateTxCollection(r, tx, key, value)
}

func (a *setvarFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func (a *setvarFn) evaluateTxCollection(r *coraza.Rule, tx *coraza.Transaction, key string, value string) {
	collection := tx.GetCollection(a.collection)
	if collection == nil {
		//fmt.Println("Invalid Collection " + a.Collection) LOG error?
		return
	}

	if a.isRemove {
		collection.Remove(a.key)
		return
	}
	res := collection.Get(a.key)
	if len(res) == 0 {
		collection.Set(tx.MacroExpansion(a.key), []string{"0"})
		res = []string{"0"}
	}
	if len(a.value) == 0 {
		collection.Set(tx.MacroExpansion(a.key), []string{""})
	} else if a.value[0] == '+' {
		me, _ := strconv.Atoi(tx.MacroExpansion(a.value[1:]))
		txv, err := strconv.Atoi(res[0])
		if err != nil {
			return
		}
		collection.Set(tx.MacroExpansion(a.key), []string{strconv.Itoa(me + txv)})
	} else if a.value[0] == '-' {
		me, _ := strconv.Atoi(tx.MacroExpansion(a.value[1:]))
		txv, err := strconv.Atoi(res[0])
		if err != nil {
			return
		}
		collection.Set(tx.MacroExpansion(a.key), []string{strconv.Itoa(txv - me)})
	} else {
		collection.Set(tx.MacroExpansion(a.key), []string{tx.MacroExpansion(a.value)})
	}
}

func setvar() coraza.RuleAction {
	return &setvarFn{}
}

var (
	_ coraza.RuleAction = &setvarFn{}
	_ RuleActionWrapper = setvar
)
