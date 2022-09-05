// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type severityFn struct {
}

func (a *severityFn) Init(r *corazawaf.Rule, data string) error {
	sev, err := types.ParseRuleSeverity(data)
	if err != nil {
		return err
	}
	r.Severity = sev
	return nil
}

func (a *severityFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// Not evaluated
}

func (a *severityFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func severity() corazawaf.RuleAction {
	return &severityFn{}
}

var (
	_ corazawaf.RuleAction = &severityFn{}
	_ ruleActionWrapper    = severity
)
