// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type captureFn struct{}

func (a *captureFn) Init(r *coraza.Rule, b1 string) error {
	// this will capture only the current rule
	r.Capture = true
	return nil
}

func (a *captureFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {

}

func (a *captureFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func capture() coraza.RuleAction {
	return &captureFn{}
}

var (
	_ coraza.RuleAction = &captureFn{}
	_ ruleActionWrapper = capture
)
