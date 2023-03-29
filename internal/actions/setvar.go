// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"
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

func (a *setvarFn) Init(_ rules.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

	if data[0] == '!' {
		a.isRemove = true
		data = data[1:]
	}

	var err error
	key, val, valOk := strings.Cut(data, "=")
	colKey, colVal, colOk := strings.Cut(key, ".")
	// Right not it only makes sense to allow setting TX
	// key is also required
	if strings.ToUpper(colKey) != "TX" {
		return errors.New("invalid arguments, expected collection TX")
	}
	if strings.TrimSpace(colVal) == "" {
		return errors.New("invalid arguments, expected syntax TX.{key}={value}")
	}
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
	tx.DebugLogger().Debug().
		Str("var_key", key).
		Str("var_value", value).
		Int("rule_id", r.ID()).
		Msg("Action evaluated")
	a.evaluateTxCollection(r, tx, strings.ToLower(key), value)
}

func (a *setvarFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func (a *setvarFn) evaluateTxCollection(r rules.RuleMetadata, tx rules.TransactionState, key string, value string) {
	var col collection.Map
	if c, ok := tx.Collection(a.collection).(collection.Map); !ok {
		tx.DebugLogger().Error().Msg("collection in setvar is not a map")
		return
	} else {
		col = c
	}
	if col == nil {
		tx.DebugLogger().Error().Msg("collection in setvar is nil")
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
				tx.DebugLogger().Error().
					Str("var_value", value).
					Int("rule_id", r.ID()).
					Err(err).
					Msg("Invalid value")
				return
			}
		}
		val := 0
		if res != "" {
			val, err = strconv.Atoi(res)
			if err != nil {
				tx.DebugLogger().Error().
					Str("var_key", res).
					Int("rule_id", r.ID()).
					Err(err).
					Msg("Invalid value")
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
