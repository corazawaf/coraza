// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type setvarFn struct {
	key        macro.Macro
	value      macro.Macro
	collection variables.RuleVariable
	isRemove   bool
}

func (a *setvarFn) Init(r rules.RuleMetadata, data string) error {
	if data == "" {
		return fmt.Errorf("setvar requires arguments")
	}

	if data[0] == '!' {
		a.isRemove = true
		data = data[1:]
	}

	var err error
	key, val, valOk := strings.Cut(data, "=")

	colKey, colVal, colOk := strings.Cut(key, ".")
	a.collection, err = variables.Parse(colKey)
	if err != nil {
		return err
	}
	if colOk {
		macro, err := macro.NewMacro(colVal)
		if err != nil {
			return err
		}
		a.key = macro
	}
	if valOk {
		macro, err := macro.NewMacro(val)
		if err != nil {
			return err
		}
		a.value = macro
	}
	return nil
}

func (a *setvarFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	key := a.key.Expand(tx)
	value := a.value.Expand(tx)
	tx.DebugLogger().Debug("[%s] Setting var %q to %q by rule %d", tx.ID(), key, value, r.ID())
	a.evaluateTxCollection(r, tx, strings.ToLower(key), value)
}

func (a *setvarFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func (a *setvarFn) evaluateTxCollection(r rules.RuleMetadata, tx rules.TransactionState, key string, value string) {
	col := (tx.Collection(a.collection)).(*collection.Map)
	if col == nil {
		// fmt.Println("Invalid Collection " + a.Collection) LOG error?
		return
	}

	if a.isRemove {
		col.Remove(key)
		return
	}
	res := ""
	if r := col.Get(key); len(r) > 0 {
		res = r[0]
	}
	var err error
	switch {
	case len(value) == 0:
		// if nothing to input
		col.Set(key, []string{""})
	case value[0] == '+':
		// if we want to sum
		sum := 0
		if len(value) > 1 {
			sum, err = strconv.Atoi(value[1:])
			if err != nil {
				tx.DebugLogger().Error("[%s] Invalid value for setvar %q on rule %d", tx.ID(), value, r.ID())
				return
			}
		}
		val := 0
		if res != "" {
			val, err = strconv.Atoi(res)
			if err != nil {
				tx.DebugLogger().Error("[%s] Invalid value for setvar %q on rule %d", tx.ID(), res, r.ID())
				return
			}
		}
		col.Set(key, []string{strconv.Itoa(sum + val)})
	case value[0] == '-':
		me, _ := strconv.Atoi(value[1:])
		txv, err := strconv.Atoi(res)
		if err != nil {
			return
		}
		col.Set(key, []string{strconv.Itoa(txv - me)})
	default:
		col.Set(key, []string{value})
	}
}

func setvar() rules.Action {
	return &setvarFn{}
}

var (
	_ rules.Action      = &setvarFn{}
	_ ruleActionWrapper = setvar
)
