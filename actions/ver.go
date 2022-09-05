// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type verFn struct {
}

func (a *verFn) Init(r *corazawaf.Rule, data string) error {
	r.Version = data
	return nil
}

func (a *verFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// Not evaluated
}

func (a *verFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func ver() corazawaf.RuleAction {
	return &verFn{}
}

var (
	_ corazawaf.RuleAction = &verFn{}
	_ ruleActionWrapper    = ver
)
