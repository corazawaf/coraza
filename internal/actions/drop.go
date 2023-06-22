// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// Action Group: Disruptive
//
// Description:
// > This action depends on each implementation, the server is instructed to drop the connection.
//
// Initiates an immediate close of the TCP connection by sending a FIN packet.
// This action is extremely useful when responding to both Brute Force and Denial of Service attacks,
// which you may want to minimize the network bandwidth and the data returned to the client.
// This action causes error message to appear in the log `(9)Bad file descriptor: core_output_filter: writing data to the network`
//
// Example:
// ```
// # The following example initiates an IP collection for tracking Basic Authentication attempts.
// # If the client exceed the threshold of more than 25 attempts in 2 minutes, it will `DROP` the subsequent connections.
// SecAction phase:1,id:109,initcol:ip=%{REMOTE_ADDR},nolog
// SecRule ARGS:login "!^$" "nolog,phase:1,id:110,setvar:ip.auth_attempt=+1,deprecatevar:ip.auth_attempt=25/120"
// SecRule IP:AUTH_ATTEMPT "@gt 25" "log,drop,phase:1,id:111,msg:'Possible Brute Force Attack'"
// ```
type dropFn struct{}

func (a *dropFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) > 0 {
		return ErrUnexpectedArguments
	}
	return nil
}

func (a *dropFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	rid := r.ID()
	if rid == noID {
		rid = r.ParentID()
	}
	tx.Interrupt(&types.Interruption{
		Status: r.Status(),
		RuleID: rid,
		Action: "drop",
	})
}

func (a *dropFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeDisruptive
}

func drop() plugintypes.Action {
	return &dropFn{}
}

var (
	_ plugintypes.Action = &dropFn{}
	_ ruleActionWrapper  = drop
)
