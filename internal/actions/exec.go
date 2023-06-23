// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Action Group: Non-disruptive
//
// Description:
// Executes an external script/binary supplied as parameter.
// The `exec` action is executed independently from any disruptive actions specified.
// External scripts will always be called with no parameters.
// Some transaction information will be placed in environment variables.
// All the usual CGI environment variables will be there.
// You should be aware that forking a threaded process results in all threads being replicated in the new process.
// Forking can therefore incur larger overhead in a multithreaded deployment.
//
// > The script you execute must write something (anything) to stdout,
// > if it doesn’t, Coraza will assume that the script failed, and will record the failure.
//
// Example:
// ```
// # Run external program on rule match
// SecRule REQUEST_URI "^/cgi-bin/script\.pl" "phase:2,id:112,t:none,t:lowercase,t:normalizePath,block,\ exec:/usr/local/apache/bin/test.sh"

// # Run Lua script on rule match
// SecRule ARGS:p attack "phase:2,id:113,block,exec:/usr/local/apache/conf/exec.lua"
// ```
type execFn struct{}

func (a *execFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}
	return nil
}

func (a *execFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *execFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func exec() plugintypes.Action {
	return &execFn{}
}

var (
	_ plugintypes.Action = &execFn{}
	_ ruleActionWrapper  = exec
)
