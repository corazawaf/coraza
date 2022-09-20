// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
)

type logdataFn struct {
}

func (a *logdataFn) Init(r rules.RuleInfo, data string) error {
	m, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).LogData = m
	return nil
}

func (a *logdataFn) Evaluate(r rules.RuleInfo, tx rules.TransactionState) {
	// TODO(anuraaga): Confirm this is internal implementation detail
	tx.(*corazawaf.Transaction).Logdata = r.(*corazawaf.Rule).LogData.Expand(tx)
}

func (a *logdataFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func logdata() rules.Action {
	return &logdataFn{}
}

var (
	_ rules.Action      = &logdataFn{}
	_ ruleActionWrapper = logdata
)
