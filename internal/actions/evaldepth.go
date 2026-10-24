// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// Action Group: Flow
//
// Description:
// Evaluates a rule chain depth first. Without it, the chain starter is matched
// against all of its targets first and the chained rules then run once, seeing
// the `MATCHED_VAR`, `MATCHED_VAR_NAME` and `TX:0`-`TX:9` values of the last
// match only. With `evalDepth`, the rest of the chain runs once per match of the
// chain starter, with the values that match produced, until a whole chain path
// matches. The same applies between chained rules that match several targets.
// Target iteration order is unspecified.
//
// Each match of a rule can make the rules after it run again, so the work has a
// soft bound. The budget is checked between parent contexts, so one rule
// evaluation may take the count past 10000. Once exhaustion is observed, the
// rest of the chain is evaluated once, breadth first, as without `evalDepth`.
// Correlation is therefore best-effort when attacker-controlled target padding
// exhausts the budget: a matching path may not be tried before fallback.
//
// Non-disruptive actions on chained rules run for every matching parent context
// attempted, including attempts whose remaining chain does not match.
//
// This action is a Coraza extension, ModSecurity always evaluates chains
// breadth first. It can only be used in the chain starter.
//
// Example:
// ```seclang
// # Deny when the argument that captured "attack2" is the one being checked.
// SecRule ARGS "@rx (attack\d+)" "id:120,phase:2,capture,chain,evalDepth,deny,msg:'Found %{TX.1}'"
//
//	SecRule TX:1 "@streq attack2" "t:none"
//
// ```
type evalDepthFn struct{}

func (a *evalDepthFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}
	r.(*corazawaf.Rule).EvalDepth = true
	return nil
}

func (a *evalDepthFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *evalDepthFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeFlow
}

func evalDepth() plugintypes.Action {
	return &evalDepthFn{}
}

var (
	_ plugintypes.Action = &evalDepthFn{}
	_ ruleActionWrapper  = evalDepth
)
