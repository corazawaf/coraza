// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type blockFn struct{}

func (a *blockFn) Init(r *corazawaf.Rule, b1 string) error {
	return nil
}

func (a *blockFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// This should never run
}

func (a *blockFn) Type() types.RuleActionType {
	return types.ActionTypeDisruptive
}

func block() corazawaf.RuleAction {
	return &blockFn{}
}

var (
	_ corazawaf.RuleAction = &blockFn{}
	_ ruleActionWrapper    = block
)
