// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type nologFn struct {
}

func (a *nologFn) Init(r *coraza.Rule, data string) error {
	r.Log = false
	r.Audit = false
	return nil
}

func (a *nologFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	r.Audit = false
}

func (a *nologFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func nolog() coraza.RuleAction {
	return &nologFn{}
}

var (
	_ coraza.RuleAction = &nologFn{}
	_ ruleActionWrapper = nolog
)
