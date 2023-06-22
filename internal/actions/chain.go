// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// Action Group: Flow
//
// Description:
// Creating a rule chain - chains the current rule with the rule that immediately follows it.
//
// Noted that rule chains simulate **AND condition**.
// The disruptive actions specified in the first portion of the chained rule will be triggered only if all of the variable checks return positive hits.
// If one of the chained rule is negative, the entire rule chain will fail to match.
//
// These action can be specified only by the chain starter rule:
// - disruptive actions
// - execution phases
// - metadata actions (id, rev, msg, tag, severity, logdata)
// - skip
// - skipAfter
//
// The following directives can be used in rule chains:
// - `SecAction`
// - `SecRule`
// - `SecRuleScript`
//
// Special rules control the usage of actions in a chained rule:
// - An action which affects the rule flow (i.e., the disruptive actions, `skip` and `skipAfter`) can be used only in the chain starter. They will be executed only if the entire chain matches.
// - Non-disruptive rules can be used in any rule; they will be executed if the rule that contains them matches and not only when the entire chain matches.
// - The metadata actions (e.g., `id`, `rev`, `msg`) can be used only in the chain starter.
//
// Example:
// ```
// # Refuse to accept POST requests that do not contain a Content-Length header.
// # Noted that the rule should be preceded by a rule that verifies only valid request methods are used.
//
//	SecRule REQUEST_METHOD "^POST$" "phase:1,chain,t:none,id:105"
//		SecRule &REQUEST_HEADERS:Content-Length "@eq 0" "t:none"
//
// ```
type chainFn struct{}

func (a *chainFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}

	r.(*corazawaf.Rule).HasChain = true
	return nil
}

func (a *chainFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *chainFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeFlow
}

func chain() plugintypes.Action {
	return &chainFn{}
}

var (
	_ plugintypes.Action = &chainFn{}
	_ ruleActionWrapper  = chain
)
