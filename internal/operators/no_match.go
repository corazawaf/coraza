// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.noMatch

package operators

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Forces the rule to always return false, effectively disabling rule matching unconditionally.
// Useful for temporarily disabling rules without removing them, or for rules that only execute
// actions without needing to match.
//
// Arguments:
// None. This operator takes no arguments.
//
// Returns:
// false (always, unconditionally)
//
// Example:
// ```
// # Disabled rule that never matches
// SecRule ARGS "@noMatch" "id:205,deny,log,msg:'This rule will never fire'"
//
// # Rule that only executes actions without matching
// SecRule REQUEST_URI "@noMatch" "id:206,pass,setvar:tx.test=1"
// ```
type noMatch struct{}

var _ plugintypes.Operator = (*noMatch)(nil)

func newNoMatch(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &noMatch{}, nil
}

func (*noMatch) Evaluate(tx plugintypes.TransactionState, value string) bool { return false }

func init() {
	Register("noMatch", newNoMatch)
}
