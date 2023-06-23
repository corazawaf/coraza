// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// Action Group: Non-disruptive
//
// Description:
// Creates, removes, or updates a variable. Variable names are **case-insensitive**.
//
// Example:
// ```
// # Create a variable and set its value to 1 (usually used for setting flags)
// `setvar:TX.score`
//
// # Create a variable and initialize it at the same time,
// `setvar:TX.score=10`
//
// # Remove a variable, prefix the name with an exclamation mark
// `setvar:!TX.score`
//
// # Increase or decrease variable value, use + and - characters in front of a numerical value
// `setvar:TX.score=+5`
//
// # Example from OWASP CRS:
//
//	SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "\bsys\.user_catalog\b" \
//		"phase:2,rev:'2.1.3',capture,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,t:replaceComments,t:compressWhiteSpace,ctl:auditLogParts=+E, \
//		block,msg:'Blind SQL Injection Attack',id:'959517',tag:'WEB_ATTACK/SQL_INJECTION',tag:'WASCTC/WASC-19',tag:'OWASP_TOP_10/A1',tag:'OWASP_AppSensor/CIE1', \
//		tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, \
//		setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/SQL_INJECTION-%{matched_var_name}=%{tx.0}"
//
// # When using in a chain, the action will be executed when an individual rule matches instead of the entire chain match.
//
//	SecRule REQUEST_FILENAME "@contains /test.php" "chain,id:7,phase:1,t:none,nolog,setvar:tx.auth_attempt=+1"
//		SecRule ARGS_POST:action "@streq login" "t:none"
//
// # Increment every time that test.php is visited (regardless of the parameters submitted).
// # If the desired goal is to set the variable only if the entire rule matches,
// # it should be included in the last rule of the chain.
//
//	SecRule REQUEST_FILENAME "@streq test.php" "chain,id:7,phase:1,t:none,nolog"
//		SecRule ARGS_POST:action "@streq login" "t:none,setvar:tx.auth_attempt=+1"
//
// ```
type setvarFn struct {
	key        macro.Macro
	value      macro.Macro
	collection variables.RuleVariable
	isRemove   bool
}

func (a *setvarFn) Init(_ plugintypes.RuleMetadata, data string) error {
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

func (a *setvarFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	key := a.key.Expand(tx)
	value := a.value.Expand(tx)
	tx.DebugLogger().Debug().
		Str("var_key", key).
		Str("var_value", value).
		Int("rule_id", r.ID()).
		Msg("Action evaluated")
	a.evaluateTxCollection(r, tx, strings.ToLower(key), value)
}

func (a *setvarFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func (a *setvarFn) evaluateTxCollection(r plugintypes.RuleMetadata, tx plugintypes.TransactionState, key string, value string) {
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

func setvar() plugintypes.Action {
	return &setvarFn{}
}

var (
	_ plugintypes.Action = &setvarFn{}
	_ ruleActionWrapper  = setvar
)
