// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/redwanghb/coraza/v3/experimental/plugins/plugintypes"
	"github.com/redwanghb/coraza/v3/internal/corazawaf"
)

// Action Group: Metadata
//
// Description:
// Assigns a tag (category) to a rule or a chain. The tag information appears along with other rule metadata.
// Tags allow easy automated categorization of events, and multiple tags can be specified on the same rule.
// You can use forward slashes to create a hierarchy of categories (see example), and it also support Macro Expansions.
//
// Example:
// ```
//
//	SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "\bgetparentfolder\b" \
//	 	"phase:2,rev:'2.1.3',capture,t:none,t:htmlEntityDecode,t:compressWhiteSpace,t:lowercase,ctl:auditLogParts=+E,block,msg:'Cross-site Scripting (XSS) Attack',id:'958016',tag:'WEB_ATTACK/XSS',tag:'WASCTC/WASC-8',tag:'WASCTC/WASC-22',tag:'OWASP_TOP_10/A2',tag:'OWASP_AppSensor/IE1',tag:'PCI/6.5.1',logdata:'% \
//		{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.xss_score=+%{tx.critical_anomaly_score},setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/XSS-%{matched_var_name}=%{tx.0}"
//
// ```
type tagFn struct{}

func (a *tagFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}
	r.(*corazawaf.Rule).Tags_ = append(r.(*corazawaf.Rule).Tags_, data)
	return nil
}

func (a *tagFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *tagFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeMetadata
}

func tag() plugintypes.Action {
	return &tagFn{}
}

var (
	_ plugintypes.Action = &tagFn{}
	_ ruleActionWrapper  = tag
)
