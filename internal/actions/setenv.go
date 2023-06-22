// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"
	"os"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Action Group: Non-disruptive
//
// Description:
// Creates, removes, and updates environment variables that can be accessed by the implementation.
// > In a trained rule, the action will be executed when an individual rule matches (not the entire chain).
//
// Example:
// ```
// SecRule RESPONSE_HEADERS:/Set-Cookie2?/ "(?i:(j?sessionid|(php)?sessid|(asp|jserv|jw)?session[-_]?(id)?|cf(id|token)|sid))" "phase:3,t:none,pass,id:139,nolog,setvar:tx.sessionid=%{matched_var}"
// SecRule TX:SESSIONID "!(?i:\;? ?httponly;?)" "phase:3,id:140,t:none,setenv:httponly_cookie=%{matched_var},pass,log,auditlog,msg:'AppDefect: Missing HttpOnly Cookie Flag.'"
//
// # In Apache
// Header set Set-Cookie "%{httponly_cookie}e; HTTPOnly" env=httponly_cookie
// ```
type setenvFn struct {
	key   string
	value macro.Macro
}

func (a *setenvFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

	key, val, ok := strings.Cut(data, "=")
	if !ok {
		return ErrInvalidKVArguments
	}

	if len(key) == 0 {
		return errors.New("missing env key")
	}

	if len(val) == 0 {
		return errors.New("missing env value")
	}

	m, err := macro.NewMacro(val)
	if err != nil {
		return err
	}
	a.key = key
	a.value = m
	return nil
}

func (a *setenvFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	v := a.value.Expand(tx)
	// set env variable
	if err := os.Setenv(a.key, v); err != nil {
		tx.DebugLogger().
			Error().
			Int("rule_id", r.ID()).
			Err(err).
			Msg("Failed to set the env variable for rule")
	}
	// TODO is this ok?
	tx.Variables().Env().Set(a.key, []string{v})

}

func (a *setenvFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func setenv() plugintypes.Action {
	return &setenvFn{}
}

var (
	_ plugintypes.Action = &setenvFn{}
	_ ruleActionWrapper  = setenv
)
