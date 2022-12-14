// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/rules"
)

type blockFn struct{}

func (a *blockFn) Init(r rules.RuleMetadata, b1 string) error {
	return nil
}

func (a *blockFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	// This should never run
}

func (a *blockFn) Type() rules.ActionType {
	return rules.ActionTypeDisruptive
}

func block() rules.Action {
	return &blockFn{}
}

var (
	_ rules.Action      = &blockFn{}
	_ ruleActionWrapper = block
)
