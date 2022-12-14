// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type nologFn struct {
}

func (a *nologFn) Init(r rules.RuleMetadata, data string) error {
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).Log = false
	r.(*corazawaf.Rule).Audit = false
	return nil
}

func (a *nologFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	// TODO(anuraaga): Confirm this is internal implementation detail
	// TODO(anuraaga): Confirm this is actually needed.
	r.(*corazawaf.Rule).Audit = false
}

func (a *nologFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func nolog() rules.Action {
	return &nologFn{}
}

var (
	_ rules.Action      = &nologFn{}
	_ ruleActionWrapper = nolog
)
