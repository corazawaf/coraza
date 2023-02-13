// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type noauditlogFn struct{}

func (a *noauditlogFn) Init(r rules.RuleMetadata, _ string) error {
	// TODO(jcchavezs): Shall we return an error if data is not empty?
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).Audit = false
	return nil
}

func (a *noauditlogFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {}

func (a *noauditlogFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func noauditlog() rules.Action {
	return &noauditlogFn{}
}

var (
	_ rules.Action      = &noauditlogFn{}
	_ ruleActionWrapper = noauditlog
)
