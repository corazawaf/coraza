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
	spl := strings.SplitN(data, "=", 2)

	splcol := strings.SplitN(spl[0], ".", 2)
	a.collection, err = variables.Parse(splcol[0])
	if err != nil {
		return err
	}
	if len(splcol) == 2 {
		macro, err := macro.NewMacro(splcol[1])
		if err != nil {
			return err
		}
		a.key = macro
	}
	if len(spl) == 2 {
		macro, err := macro.NewMacro(spl[1])
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
	tx.DebugLogger().Debug("[%s] Setting var %q to %q by rule %d", tx.GetID(), key, value, r.GetID())
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
				tx.DebugLogger().Error("[%s] Invalid value for setvar %q on rule %d", tx.GetID(), value, r.GetID())
				return
			}
		}
		val := 0
		if res != "" {
			val, err = strconv.Atoi(res)
			if err != nil {
				tx.DebugLogger().Error("[%s] Invalid value for setvar %q on rule %d", tx.GetID(), res, r.GetID())
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
