// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
)

type appendFn struct {
	data macro.Macro
}

func (a *appendFn) Init(r rules.RuleMetadata, data string) error {
	macro, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	a.data = macro
	return nil
}

func (a *appendFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	if !tx.ContentInjection() {
		tx.DebugLogger().Debug("append rejected because of ContentInjection")
		return
	}
	data := a.data.Expand(tx)
	// TODO: elaborate on ContentInjection actions considering that the WAF may NOT buffer the whole response
	if it, _, err := tx.WriteResponseBody([]byte(data)); it != nil || err != nil {
		tx.DebugLogger().Error("append failed to write to response buffer: %s", err.Error())
	}
}

func (a *appendFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func append2() rules.Action {
	return &appendFn{}
}

var (
	_ rules.Action      = &appendFn{}
	_ ruleActionWrapper = append2
)
