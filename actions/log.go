// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type logFn struct {
}

func (a *logFn) Init(r *corazawaf.Rule, data string) error {
	r.Log = true
	r.Audit = true
	return nil
}

func (a *logFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
}

func (a *logFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func log() corazawaf.RuleAction {
	return &logFn{}
}

var (
	_ corazawaf.RuleAction = &logFn{}
	_ ruleActionWrapper    = log
)
