// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/rules"
)

type expirevarFn struct{}

func (a *expirevarFn) Init(_ rules.RuleMetadata, data string) error {
	return nil
}

func (a *expirevarFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	// Not supported
	tx.DebugLogger().Warn().Int("rule_id", r.ID()).Msg("Expirevar was used but it's not supported")
}

func (a *expirevarFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func expirevar() rules.Action {
	return &expirevarFn{}
}

var (
	_ rules.Action      = &expirevarFn{}
	_ ruleActionWrapper = expirevar
)
