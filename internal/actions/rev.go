// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// Action Group: Metadata
//
// Description:
// Specifies the rule revision. This action is used in combination with action `id` to allow the same rule ID to be used after changes,
// and it can still provide some indication about the rule changes.
//
// Example:
// ```
//
//	SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "(?:(?:[\;\|\`]\W*?\bcc|\b(wget|curl))\b|\/cc(?:[\'\"\|\;\`\-\s]|$))" \
//		"phase:2,rev:'2.1.3',capture,t:none,t:normalizePath,t:lowercase,ctl:auditLogParts=+E,block,msg:'System Command Injection',id:'950907',tag:'WEB_ATTACK/COMMAND_INJECTION',tag:'WASCTC/WASC-31',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2',logdata:'%{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.command_injection_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/COMMAND_INJECTION-%{matched_var_name}=%{tx.0},skipAfter:END_COMMAND_INJECTION1"
//
// ```
type revFn struct{}

func (a *revFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}
	r.(*corazawaf.Rule).Rev_ = data
	return nil
}

func (a *revFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *revFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeMetadata
}

func rev() plugintypes.Action {
	return &revFn{}
}

var (
	_ plugintypes.Action = &revFn{}
	_ ruleActionWrapper  = rev
)
