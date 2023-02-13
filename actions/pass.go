// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/rules"
)

type passFn struct{}

func (a *passFn) Init(_ rules.RuleMetadata, _ string) error {
	// TODO(jcchavezs): Shall we return an error if data is not empty?
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
