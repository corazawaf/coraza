// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type multimatchFn struct {
}

func (a *multimatchFn) Init(r *corazawaf.Rule, data string) error {
	r.MultiMatch = true
	return nil
}

func (a *multimatchFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// Not evaluated
}

func (a *multimatchFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func multimatch() corazawaf.RuleAction {
	return &multimatchFn{}
}

var (
	_ corazawaf.RuleAction = &multimatchFn{}
	_ ruleActionWrapper    = multimatch
)
