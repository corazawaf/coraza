// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"os"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type setenvFn struct {
	key   string
	value coraza.Macro
}

func (a *setenvFn) Init(r *coraza.Rule, data string) error {
	spl := strings.SplitN(data, "=", 2)
	if len(spl) != 2 {
		return fmt.Errorf("invalid key value for setvar")
	}
	a.key = spl[0]
	macro, err := coraza.NewMacro(spl[1])
	if err != nil {
		return err
	}
	a.value = *macro
	return nil
}

func (a *setenvFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	v := a.value.Expand(tx)
	// set env variable
	if err := os.Setenv(a.key, v); err != nil {
		tx.Waf.Logger.Error("[%s] Error setting env variable for rule %d: %v", tx.ID, r.ID, err)
	}
	// TODO is this ok?
	tx.Variables.Env.Set(a.key, []string{v})

}

func (a *setenvFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func setenv() coraza.RuleAction {
	return &setenvFn{}
}

var (
	_ coraza.RuleAction = &setenvFn{}
	_ ruleActionWrapper = setenv
)
