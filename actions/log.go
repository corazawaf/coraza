// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type logFn struct {
}

func (a *logFn) Init(r rules.RuleInfo, data string) error {
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).Log = true
	r.(*corazawaf.Rule).Audit = true
	return nil
}

func (a *logFn) Evaluate(r rules.RuleInfo, tx rules.TransactionState) {
}

func (a *logFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func log() rules.Action {
	return &logFn{}
}

var (
	_ rules.Action      = &logFn{}
	_ ruleActionWrapper = log
)
