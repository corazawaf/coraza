// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v4/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v4/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v4/internal/corazawaf"
)

// Action Group: Non-disruptive
//
// Description:
// Logs a data fragment as part of the alert message.
// The logdata information appears in the error and/or audit log files. Macro expansion is performed,
// so you may use variable names such as %{TX.0} or %{MATCHED_VAR}.
// The information is properly escaped for use with logging of binary data.
//
// Example:
// ```
// SecRule ARGS:p "@rx <script>" "phase:2,id:118,log,pass,logdata:%{MATCHED_VAR}"
// ```
type logdataFn struct{}

func (a *logdataFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

	m, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	r.(*corazawaf.Rule).LogData = m
	return nil
}

func (a *logdataFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	// logdata macro expansion is performed after all other actions have been evaluated (and potentially all the needed variables have been set)
}

func (a *logdataFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func logdata() plugintypes.Action {
	return &logdataFn{}
}

var (
	_ plugintypes.Action = &logdataFn{}
	_ ruleActionWrapper  = logdata
)
