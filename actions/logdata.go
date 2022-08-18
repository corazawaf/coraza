// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type logdataFn struct {
}

func (a *logdataFn) Init(r *coraza.Rule, data string) error {
	macro, err := coraza.NewMacro(data)
	if err != nil {
		return err
	}
	r.LogData = *macro
	return nil
}

func (a *logdataFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	tx.Logdata = r.LogData.Expand(tx)
}

func (a *logdataFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func logdata() coraza.RuleAction {
	return &logdataFn{}
}

var (
	_ coraza.RuleAction = &logdataFn{}
	_ ruleActionWrapper = logdata
)
