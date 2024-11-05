// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazatypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// Action Group: Disruptive
//
// Description:
// Stops rule processing on a successful match and allows a transaction to be proceed.
//
// - Using solely: allow will affect the entire transaction.
// stopping processing of the current phase but also skipping over all other phases apart from the logging phase.
// (The logging phase is special; it is designed to be always execute.)
// - Using with parameter `phase`: the engine will stop processing the current phase, and the other phases will continue.
// - Using with parameter `request`: engine will stop processing the current phase, and the next phase to be processed will be phase `types.PhaseResponseHeaders`.
//
// Example:
// ```
// # Allow unrestricted access from 192.168.1.100
// SecRule REMOTE_ADDR "^192\.168\.1\.100$" phase:1,id:95,nolog,allow
//
// # Do not process request but process response
// SecAction phase:1,allow:request,id:96
//
// # Do not process transaction (request and response).
// SecAction phase:1,allow,id:97
//
// # If you want to allow a response through, put a rule in phase RESPONSE_HEADERS and use allow
// SecAction phase:3,allow,id:98
// ```
type allowFn struct {
	allow corazatypes.AllowType
}

func (a *allowFn) Init(_ plugintypes.RuleMetadata, data string) error {
	switch data {
	case "phase":
		a.allow = corazatypes.AllowTypePhase // skip current phase
	case "request":
		a.allow = corazatypes.AllowTypeRequest // skip phases until RESPONSE_HEADERS
	case "":
		a.allow = corazatypes.AllowTypeAll // skip all phases
	default:
		return fmt.Errorf("invalid argument %q", data)
	}
	return nil
}

func (a *allowFn) Evaluate(r plugintypes.RuleMetadata, txS plugintypes.TransactionState) {
	tx := txS.(*corazawaf.Transaction)
	tx.AllowType = a.allow
}

func (a *allowFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeDisruptive
}

func allow() plugintypes.Action {
	return &allowFn{}
}

var (
	_ plugintypes.Action = (*allowFn)(nil)
	_ ruleActionWrapper  = allow
)
