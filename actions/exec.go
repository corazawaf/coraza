// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/rules"
)

type execFn struct {
}

func (a *execFn) Init(r rules.Rule, data string) error {
	return nil
}

func (a *execFn) Evaluate(r rules.Rule, tx rules.TransactionState) {
	// Not implemented
}

func (a *execFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func exec() rules.Action {
	return &execFn{}
}

var (
	_ rules.Action      = &execFn{}
	_ ruleActionWrapper = exec
)
