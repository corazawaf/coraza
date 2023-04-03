// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/rules"
)

type passFn struct{}

func (a *passFn) Init(_ rules.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}
	return nil
}

func (a *passFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {}

func (a *passFn) Type() rules.ActionType {
	return rules.ActionTypeDisruptive
}

func pass() rules.Action {
	return &passFn{}
}

var (
	_ rules.Action      = &passFn{}
	_ ruleActionWrapper = pass
)
