// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type severityFn struct{}

func (a *severityFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

	sev, err := types.ParseRuleSeverity(data)
	if err != nil {
		return err
	}
	r.(*corazawaf.Rule).Severity_ = sev
	return nil
}

func (a *severityFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *severityFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeMetadata
}

func severity() plugintypes.Action {
	return &severityFn{}
}

var (
	_ plugintypes.Action = &severityFn{}
	_ ruleActionWrapper  = severity
)
