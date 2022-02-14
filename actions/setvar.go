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
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types"
	"github.com/corazawaf/coraza/v2/types/variables"
	"go.uber.org/zap"
)

type setvarFn struct {
	key        coraza.Macro
	value      coraza.Macro
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
	a.collection, err = variables.Parse(splcol[0])
	if err != nil {
		return err
	}
	if len(splcol) == 2 {
		macro, err := coraza.NewMacro(splcol[1])
		if err != nil {
			return err
		}
		a.key = *macro
	}
	if len(spl) == 2 {
		macro, err := coraza.NewMacro(spl[1])
		if err != nil {
			return err
		}
		a.value = *macro
	}
	return nil
}

func (a *setvarFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	key := a.key.Expand(tx)
	value := a.value.Expand(tx)
	tx.Waf.Logger.Debug("Setting var", zap.String("key", key), zap.String("value", value))
	a.evaluateTxCollection(r, tx, strings.ToLower(key), value)
}

func (a *setvarFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func (a *setvarFn) evaluateTxCollection(r *coraza.Rule, tx *coraza.Transaction, key string, value string) {
	collection := tx.GetCollection(a.collection)
	if collection == nil {
		// fmt.Println("Invalid Collection " + a.Collection) LOG error?
		return
	}

	if a.isRemove {
		collection.Remove(key)
		return
	}
	res := ""
	if r := collection.Get(key); len(r) > 0 {
		res = r[0]
	}
	var err error
	switch {
	case len(value) == 0:
		// if nothing to input
		collection.Set(key, []string{""})
	case value[0] == '+':
		// if we want to sum
		sum := 0
		if len(value) > 1 {
			sum, err = strconv.Atoi(value[1:])
			if err != nil {
				tx.Waf.Logger.Error("Invalid value for setvar", zap.String("value", value))
				return
			}
		}
		val := 0
		if res != "" {
			val, err = strconv.Atoi(res)
			if err != nil {
				tx.Waf.Logger.Error("Invalid value for setvar", zap.String("value", res))
				return
			}
		}
		collection.Set(key, []string{strconv.Itoa(sum + val)})
	case value[0] == '-':
		me, _ := strconv.Atoi(value[1:])
		txv, err := strconv.Atoi(res)
		if err != nil {
			return
		}
		collection.Set(key, []string{strconv.Itoa(txv - me)})
	default:
		collection.Set(key, []string{value})
	}
}

func setvar() coraza.RuleAction {
	return &setvarFn{}
}

var (
	_ coraza.RuleAction = &setvarFn{}
	_ ruleActionWrapper = setvar
)
