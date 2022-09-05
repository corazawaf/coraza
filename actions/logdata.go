// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type logdataFn struct {
}

func (a *logdataFn) Init(r *corazawaf.Rule, data string) error {
	macro, err := corazawaf.NewMacro(data)
	if err != nil {
		return err
	}
	r.LogData = *macro
	return nil
}

func (a *logdataFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	tx.Logdata = r.LogData.Expand(tx)
}

func (a *logdataFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func logdata() corazawaf.RuleAction {
	return &logdataFn{}
}

var (
	_ corazawaf.RuleAction = &logdataFn{}
	_ ruleActionWrapper    = logdata
)
