// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/corazawaf/coraza/v3/types"
)

type severityFn struct {
}

func (a *severityFn) Init(r rules.RuleMetadata, data string) error {
	sev, err := types.ParseRuleSeverity(data)
	if err != nil {
		return err
	}
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).Severity_ = sev
	return nil
}

func (a *severityFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {}

func (a *severityFn) Type() rules.ActionType {
	return rules.ActionTypeMetadata
}

func severity() rules.Action {
	return &severityFn{}
}

var (
	_ rules.Action      = &severityFn{}
	_ ruleActionWrapper = severity
)
