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

func (a *setenvFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
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
