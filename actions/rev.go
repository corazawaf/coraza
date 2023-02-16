// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type revFn struct{}

func (a *revFn) Init(r rules.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}
	r.(*corazawaf.Rule).Rev_ = data
	return nil
}

func (a *revFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {}

func (a *revFn) Type() rules.ActionType {
	return rules.ActionTypeMetadata
}

func rev() rules.Action {
	return &revFn{}
}

var (
	_ rules.Action      = &revFn{}
	_ ruleActionWrapper = rev
)
