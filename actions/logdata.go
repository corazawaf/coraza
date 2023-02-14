// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"
	"fmt"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
)

type logdataFn struct{}

func (a *logdataFn) Init(r rules.RuleMetadata, data string) error {
	if len(data) == 0 {
		return errors.New("logdata requires an argument")
	}

	// TODO(jcchavezs): makes macro fail if data is empty
	m, err := macro.NewMacro(data)
	if err != nil {
		return fmt.Errorf("invalid argument for logdata: %s", err.Error())
	}
	r.(*corazawaf.Rule).LogData = m
	return nil
}

func (a *logdataFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
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
