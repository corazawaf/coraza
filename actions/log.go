// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type logFn struct {
}

func (a *logFn) Init(r *coraza.Rule, data string) error {
	r.Log = true
	r.Audit = true
	return nil
}

func (a *logFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
}

func (a *logFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func log() coraza.RuleAction {
	return &logFn{}
}

var (
	_ coraza.RuleAction = &logFn{}
	_ ruleActionWrapper = log
)
