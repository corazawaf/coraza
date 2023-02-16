// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"
	"os"
	"strings"

	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
)

type setenvFn struct {
	key   string
	value macro.Macro
}

func (a *setenvFn) Init(_ rules.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

	key, val, ok := strings.Cut(data, "=")
	if !ok {
		return ErrInvalidKVArguments
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

func (a *setenvFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	v := a.value.Expand(tx)
	// set env variable
	if err := os.Setenv(a.key, v); err != nil {
		tx.DebugLogger().Error("[%s] Error setting env variable for rule %d: %s", tx.ID(), r.ID(), err.Error())
	}
	// TODO is this ok?
	tx.Variables().Env().Set(a.key, []string{v})

}

func (a *setenvFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func setenv() rules.Action {
	return &setenvFn{}
}

var (
	_ rules.Action      = &setenvFn{}
	_ ruleActionWrapper = setenv
)
