// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type multimatchFn struct {
}

func (a *multimatchFn) Init(r rules.RuleMetadata, data string) error {
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).MultiMatch = true
	return nil
}

func (a *multimatchFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	// Not evaluated
}

func (a *multimatchFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func multimatch() rules.Action {
	return &multimatchFn{}
}

var (
	_ rules.Action      = &multimatchFn{}
	_ ruleActionWrapper = multimatch
)
