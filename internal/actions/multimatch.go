// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/redwanghb/coraza/v3/experimental/plugins/plugintypes"
	"github.com/redwanghb/coraza/v3/internal/corazawaf"
)

// Action Group: Non-disruptive
//
// Description:
// Perform multiple operator invocations for every target, before and after every anti-evasion transformation is performed.
// Normally, variables are inspected only once per rule, and only after all transformation functions have been completed.
// With multiMatch, variables are checked against the operator before and after every transformation function that changes the input.
//
// Example:
// ```
// SecRule ARGS "attack" "phase1,log,deny,id:119,t:removeNulls,t:lowercase,multiMatch"
// ```
type multimatchFn struct{}

func (a *multimatchFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}
	r.(*corazawaf.Rule).MultiMatch = true
	return nil
}

func (a *multimatchFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *multimatchFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func multimatch() plugintypes.Action {
	return &multimatchFn{}
}

var (
	_ plugintypes.Action = &multimatchFn{}
	_ ruleActionWrapper  = multimatch
)
