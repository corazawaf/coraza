// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type captureFn struct{}

func (a *captureFn) Init(r *corazawaf.Rule, b1 string) error {
	// this will capture only the current rule
	r.Capture = true
	return nil
}

func (a *captureFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {

}

func (a *captureFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func capture() corazawaf.RuleAction {
	return &captureFn{}
}

var (
	_ corazawaf.RuleAction = &captureFn{}
	_ ruleActionWrapper    = capture
)
