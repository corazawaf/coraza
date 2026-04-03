// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.unconditionalMatch

package operators

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Forces the rule to always return true, unconditionally matching and firing all associated actions.
// Useful for rules that should always execute their actions regardless of input, such as setting
// variables, logging, or performing initialization tasks.
//
// Arguments:
// None. This operator takes no arguments.
//
// Returns:
// true (always, unconditionally)
//
// Example:
// ```
// # Always execute action to set variable
// SecRule REMOTE_ADDR "@unconditionalMatch" "id:207,phase:1,pass,nolog,setvar:tx.initialized=1"
//
// # Force rule to always match and log
// SecRule REQUEST_URI "@unconditionalMatch" "id:208,pass,log,msg:'Request logged'"
// ```
type unconditionalMatch struct{}

func newUnconditionalMatch(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &unconditionalMatch{}, nil
}

func (*unconditionalMatch) Evaluate(plugintypes.TransactionState, string) bool { return true }

func init() {
	Register("unconditionalMatch", newUnconditionalMatch)
}
