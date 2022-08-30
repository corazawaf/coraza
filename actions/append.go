// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type appendFn struct {
	data coraza.Macro
}

func (a *appendFn) Init(r *coraza.Rule, data string) error {
	macro, err := coraza.NewMacro(data)
	if err != nil {
		return err
	}
	a.data = *macro
	return nil
}

func (a *appendFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	if !tx.Waf.ContentInjection {
		tx.Waf.Logger.Debug("append rejected because of ContentInjection")
		return
	}
	data := a.data.Expand(tx)
	if _, err := tx.ResponseBodyBuffer.Write([]byte(data)); err != nil {
		tx.Waf.Logger.Error("append failed to write to response buffer: %s", err.Error())
	}
}

func (a *appendFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func append2() coraza.RuleAction {
	return &appendFn{}
}

var (
	_ coraza.RuleAction = &appendFn{}
	_ ruleActionWrapper = append2
)
