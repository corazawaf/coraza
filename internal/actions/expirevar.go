// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Action Group: Non-disruptive
//
// Description:
// Configures a collection variable to expire after the given time period (in seconds).
// You should use the `expirevar` with `setvar` action to keep the intended expiration time.
// The expire time will be reset if they are used on their own (perhaps in a SecAction directive).
//
// Example:
// ```
//
//	SecRule REQUEST_COOKIES:JSESSIONID "!^$" "nolog,phase:1,id:114,pass,setsid:%{REQUEST_COOKIES:JSESSIONID}"
//
//	SecRule REQUEST_URI "^/cgi-bin/script\.pl" "phase:2,id:115,t:none,t:lowercase,t:normalizePath,log,allow,\
//		setvar:session.suspicious=1,expirevar:session.suspicious=3600,phase:1"
//
// ```
type expirevarFn struct{}

func (a *expirevarFn) Init(_ plugintypes.RuleMetadata, data string) error {
	return nil
}

func (a *expirevarFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	// Not supported
	tx.DebugLogger().Warn().Int("rule_id", r.ID()).Msg("Expirevar was used but it's not supported")
}

func (a *expirevarFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func expirevar() plugintypes.Action {
	return &expirevarFn{}
}

var (
	_ plugintypes.Action = &expirevarFn{}
	_ ruleActionWrapper  = expirevar
)
