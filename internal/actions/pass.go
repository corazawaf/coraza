// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Action Group: Disruptive
//
// Description:
// Continues processing with the next rule in spite of a successful match.
//
// Example:
// ```
// SecRule REQUEST_HEADERS:User-Agent "@streq Test" "log,pass,id:122"
//
// # When using pass with a SecRule with multiple targets,
// # all variables will be inspected and all non-disruptive actions trigger for every match.
// # In the following example, the TX.test variable will be incremented once for every request parameter
//
// # Set TX.test to zero
// SecAction "phase:2,nolog,pass,setvar:TX.test=0,id:123"
//
// # Increment TX.test for every request parameter
// SecRule ARGS "test" "phase:2,log,pass,setvar:TX.test=+1,id:124"
// ```
type passFn struct{}

func (a *passFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}
	return nil
}

func (a *passFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *passFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeDisruptive
}

func pass() plugintypes.Action {
	return &passFn{}
}

var (
	_ plugintypes.Action = &passFn{}
	_ ruleActionWrapper  = pass
)
