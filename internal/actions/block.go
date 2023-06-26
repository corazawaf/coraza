// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Action Group: Disruptive
//
// Description:
// Performs the disruptive action defined by the previous `SecDefaultAction`.
// This action is a placeholder to be used by rule writers to request a blocking action,
// but without specifying how the blocking is to be done.
// The idea is that such decisions are best left to rule users, as well as to allow users, to override blocking for their demands.
// In future versions of Coraza, more control and functionality will be added to define "how" to block.
//
// Example:
// ```
// # Specify how blocking is to be done
// SecDefaultAction "phase:2,deny,id:101,status:403,log,auditlog"
//
// # Detect attacks where we want to block
// SecRule ARGS "@rx attack1" "phase:2,block,id:102"
//
// # Detect attacks where we want only to warn
// SecRule ARGS "@rx attack2" "phase:2,pass,id:103"
//
// # It is possible to use the `SecRuleUpdateActionById` directive to override how a rule handles blocking.
// # This is useful in three cases:
//
// # 1. If a rule has blocking hard-coded, and you want it to use the policy you determine.
// # 2. If a rule was written to `block`, but you want it to warn only.
// # 3. If a rule was written to only `warn`, but you want it to block.
//
// # The following example demonstrates the first case,
// # in which the hard-coded block is removed in favor of the user-controllable block:
//
// # Specify how blocking is to be done
// SecDefaultAction "phase:2,deny,status:403,log,auditlog,id:104"
//
// # Detect attacks and block
// SecRule ARGS "@rx attack1" "phase:2,id:1,deny"
//
// # Change how rule ID 1 blocks
// SecRuleUpdateActionById 1 "block"
// ```
type blockFn struct{}

func (a *blockFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}

	return nil
}

func (a *blockFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {
	// This should never run
	// TODO(jcchavezs): check if we return a panic
}

func (a *blockFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeDisruptive
}

func block() plugintypes.Action {
	return &blockFn{}
}

var (
	_ plugintypes.Action = &blockFn{}
	_ ruleActionWrapper  = block
)
