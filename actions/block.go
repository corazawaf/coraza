// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type blockFn struct{}

func (a *blockFn) Init(r *coraza.Rule, b1 string) error {
	return nil
}

func (a *blockFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// This should never run
}

func (a *blockFn) Type() types.RuleActionType {
	return types.ActionTypeDisruptive
}

func block() coraza.RuleAction {
	return &blockFn{}
}

var (
	_ coraza.RuleAction = &blockFn{}
	_ ruleActionWrapper = block
)
