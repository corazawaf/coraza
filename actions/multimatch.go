// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type multimatchFn struct {
}

func (a *multimatchFn) Init(r *coraza.Rule, data string) error {
	r.MultiMatch = true
	return nil
}

func (a *multimatchFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *multimatchFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func multimatch() coraza.RuleAction {
	return &multimatchFn{}
}

var (
	_ coraza.RuleAction = &multimatchFn{}
	_ ruleActionWrapper = multimatch
)
