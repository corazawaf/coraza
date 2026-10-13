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
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types/variables"
)

var supportedColKeys = []string{"TX", "USER", "GLOBAL", "RESOURCE", "SESSION", "IP"}

// Action Group: Non-disruptive
//
// Description:
// Creates, removes, or updates a variable. Variable names are **case-insensitive**.
//
// Example:
// ```seclang
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
	// we validate uppercase colKey is one of supported
	if !utils.InSlice(strings.ToUpper(colKey), supportedColKeys) {
		return errors.New("setvar: invalid editable collection, supported collections are: " + strings.Join(supportedColKeys, ", "))
	}
	if strings.TrimSpace(colVal) == "" {
		return errors.New("invalid arguments, expected syntax {key}={value}")
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
		Msg("Action SetVar evaluated")
	a.evaluateTxCollection(r, tx, strings.ToLower(key), value)
}

func (a *setvarFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func (a *setvarFn) evaluateTxCollection(r plugintypes.RuleMetadata, tx plugintypes.TransactionState, key string, value string) {
	col := tx.Collection(a.collection)

	switch c := col.(type) {
	case collection.Persistent:
		tx.DebugLogger().Debug().Msg("Handling setvar for a Persistent collection")
		if a.isRemove {
			c.Remove(key)
			return
		}

		if len(value) > 0 && (value[0] == '+' || value[0] == '-') {
			val, err := strconv.Atoi(value[1:])
			if err != nil {
				// Not a valid number after +/-. Treat as a regular string set.
				c.SetOne(key, value)
				return
			}
			if value[0] == '-' {
				val = -val
			}
			c.Sum(key, val)
		} else {
			c.SetOne(key, value)
		}

	case collection.Map:
		// Logic for Map collections - tx only
		tx.DebugLogger().Debug().Msg("Handling setvar for a Map collection")
		if a.isRemove {
			c.Remove(key)
			return
		}

		currentVal := ""
		if r := c.Get(key); len(r) > 0 {
			currentVal = r[0]
		}

		switch {
		case len(value) > 0 && (value[0] == '+' || value[0] == '-'):
			val, err := strconv.Atoi(value[1:])
			if err != nil {
				if strings.HasPrefix(value[1:], "tx.") {
					tx.DebugLogger().Error().
						Str("var_value", value).
						Int("rule_id", r.ID()).
						Err(err).
						Msg(value)
					return
				}
				c.Set(key, []string{value})
				return
			}

			currentValInt := 0
			if currentVal != "" {
				currentValInt, err = strconv.Atoi(currentVal)
				if err != nil {
					tx.DebugLogger().Error().
						Str("var_key", currentVal).
						Int("rule_id", r.ID()).
						Err(err).
						Msg("Invalid value")
					return
				}
			}

			if value[0] == '+' {
				c.Set(key, []string{strconv.Itoa(currentValInt + val)})
			} else {
				c.Set(key, []string{strconv.Itoa(currentValInt - val)})
			}
		default:
			c.Set(key, []string{value})
		}

	default:
		tx.DebugLogger().Error().Msg("setvar: collection is not a supported editable type (Persistent or Map)")
	}
}

func setvar() plugintypes.Action {
	return &setvarFn{}
}

var (
	_ plugintypes.Action = &setvarFn{}
	_ ruleActionWrapper  = setvar
)
