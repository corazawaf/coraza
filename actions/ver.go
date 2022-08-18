// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type verFn struct {
}

func (a *verFn) Init(r *coraza.Rule, data string) error {
	r.Version = data
	return nil
}

func (a *verFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *verFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func ver() coraza.RuleAction {
	return &verFn{}
}

var (
	_ coraza.RuleAction = &verFn{}
	_ ruleActionWrapper = ver
)
