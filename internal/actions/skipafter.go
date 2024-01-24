// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v4/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v4/internal/corazawaf"
	utils "github.com/corazawaf/coraza/v4/internal/strings"
)

// Action Group: Flow
//
// Description:
// Action `skipAfter` is similar to `skip`, it skip one or more rules (or chained rules) on a successful match,
// **and resuming rule execution with the first rule that follows the rule (or marker created by SecMarker) with the provided ID)).
// The `skipAfter` action works only within the current processing phase and not necessarily the order in which the rules appear in the configuration file.
//
// Example:
// ```
// # The following rules implement the same logic as the skip example, but using skipAfter:
// # Require Accept header, but not from access from the localhost
// SecRule REMOTE_ADDR "^127\.0\.0\.1$" "phase:1,id:143,skipAfter:IGNORE_LOCALHOST"
//
// # This rule will be skipped over when REMOTE_ADDR is 127.0.0.1
// SecRule &REQUEST_HEADERS:Accept "@eq 0" "phase:1,deny,id:144,msg:'Request Missing an Accept Header'"
// SecMarker IGNORE_LOCALHOST
//
// # another Example from the OWASP CRS
// SecMarker BEGIN_HOST_CHECK
//
//	SecRule &REQUEST_HEADERS:Host "@eq 0" \
//		"skipAfter:END_HOST_CHECK,phase:2,rev:'2.1.3',t:none,block,msg:'Request Missing a Host Header',id:'960008',tag:'PROTOCOL_VIOLATION/MISSING_HEADER_HOST',tag:'WASCTC/WASC-21', \
//		tag:'OWASP_TOP_10/A7',tag:'PCI/6.5.10',severity:'5',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.notice_anomaly_score}, \
//		setvar:tx.protocol_violation_score=+%{tx.notice_anomaly_score},setvar:tx.%{rule.id}-PROTOCOL_VIOLATION/MISSING_HEADER-%{matched_var_name}=%{matched_var}"
//
//	SecRule REQUEST_HEADERS:Host "^$" \
//		"phase:2,rev:'2.1.3',t:none,block,msg:'Request Missing a Host Header',id:'960008',tag:'PROTOCOL_VIOLATION/MISSING_HEADER_HOST',tag:'WASCTC/WASC-21',tag:'OWASP_TOP_10/A7', \
//		tag:'PCI/6.5.10',severity:'5',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.notice_anomaly_score},setvar:tx.protocol_violation_score=+%{tx.notice_anomaly_score}, \
//		setvar:tx.%{rule.id}-PROTOCOL_VIOLATION/MISSING_HEADER-%{matched_var_name}=%{matched_var}"
//
// SecMarker END_HOST_CHECK
// ```
type skipafterFn struct {
	data string
}

func (a *skipafterFn) Init(_ plugintypes.RuleMetadata, data string) error {
	data = utils.MaybeRemoveQuotes(data)
	if len(data) == 0 {
		return ErrMissingArguments
	}
	a.data = data
	return nil
}

func (a *skipafterFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	tx.DebugLogger().Debug().
		Str("value", a.data).
		Msg("Starting secmarker")
	tx.(*corazawaf.Transaction).SkipAfter = a.data
}

func (a *skipafterFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeFlow
}

func skipafter() plugintypes.Action {
	return &skipafterFn{}
}

var (
	_ plugintypes.Action = &skipafterFn{}
	_ ruleActionWrapper  = skipafter
)
