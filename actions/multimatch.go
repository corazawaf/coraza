// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type multimatchFn struct{}

func (a *multimatchFn) Init(r rules.RuleMetadata, _ string) error {
	// TODO(jcchavezs): Shall we return an error if data is not empty?
	r.(*corazawaf.Rule).MultiMatch = true
	return nil
}

func (a *multimatchFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {}

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
