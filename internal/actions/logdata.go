// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type logdataFn struct{}

func (a *logdataFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

	m, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	r.(*corazawaf.Rule).LogData = m
	return nil
}

func (a *logdataFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	tx.(*corazawaf.Transaction).Logdata = r.(*corazawaf.Rule).LogData.Expand(tx)
}

func (a *logdataFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func logdata() plugintypes.Action {
	return &logdataFn{}
}

var (
	_ plugintypes.Action = &logdataFn{}
	_ ruleActionWrapper  = logdata
)
