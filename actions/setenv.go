// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"os"
	"strings"

	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
)

type setenvFn struct {
	key   string
	value macro.Macro
}

func (a *setenvFn) Init(r rules.RuleInfo, data string) error {
	spl := strings.SplitN(data, "=", 2)
	if len(spl) != 2 {
		return fmt.Errorf("invalid key value for setvar")
	}
	a.key = spl[0]
	m, err := macro.NewMacro(spl[1])
	if err != nil {
		return err
	}
	a.value = m
	return nil
}

func (a *setenvFn) Evaluate(r rules.RuleInfo, tx rules.TransactionState) {
	v := a.value.Expand(tx)
	// set env variable
	if err := os.Setenv(a.key, v); err != nil {
		tx.DebugLogger().Error("[%s] Error setting env variable for rule %d: %s", tx.GetID(), r.GetID(), err.Error())
	}
	// TODO is this ok?
	tx.GetVariables().GetEnv().Set(a.key, []string{v})

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
