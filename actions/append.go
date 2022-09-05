// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type appendFn struct {
	data corazawaf.Macro
}

func (a *appendFn) Init(r *corazawaf.Rule, data string) error {
	macro, err := corazawaf.NewMacro(data)
	if err != nil {
		return err
	}
	a.data = *macro
	return nil
}

func (a *appendFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	if !tx.WAF.ContentInjection {
		tx.WAF.Logger.Debug("append rejected because of ContentInjection")
		return
	}
	data := a.data.Expand(tx)
	if _, err := tx.ResponseBodyBuffer.Write([]byte(data)); err != nil {
		tx.WAF.Logger.Error("append failed to write to response buffer: %s", err.Error())
	}
}

func (a *appendFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func append2() corazawaf.RuleAction {
	return &appendFn{}
}

var (
	_ corazawaf.RuleAction = &appendFn{}
	_ ruleActionWrapper    = append2
)
