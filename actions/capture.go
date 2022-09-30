// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type captureFn struct{}

func (a *captureFn) Init(r rules.RuleMetadata, b1 string) error {
	// this will capture only the current rule
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).Capture = true
	return nil
}

func (a *captureFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {

}

func (a *captureFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func capture() rules.Action {
	return &captureFn{}
}

var (
	_ rules.Action      = &captureFn{}
	_ ruleActionWrapper = capture
)
