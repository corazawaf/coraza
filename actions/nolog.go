// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type nologFn struct {
}

func (a *nologFn) Init(r *corazawaf.Rule, data string) error {
	r.Log = false
	r.Audit = false
	return nil
}

func (a *nologFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	r.Audit = false
}

func (a *nologFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func nolog() corazawaf.RuleAction {
	return &nologFn{}
}

var (
	_ corazawaf.RuleAction = &nologFn{}
	_ ruleActionWrapper    = nolog
)
