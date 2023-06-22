// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// Action Group: Metadata
//
// Description:
// Specifies the relative maturity level of the rule related to the length of time a rule has been public and the amount of testing it has received.
// The value is a string based on a numeric scale (1-9 where 9 is extensively tested and 1 is a brand new experimental rule).
//
// Example:
// ```
//
//	SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "\bgetparentfolder\b" \
//		"phase:2,ver:'CRS/2.2.4,accuracy:'9',maturity:'9',capture,t:none,t:htmlEntityDecode,t:compressWhiteSpace,t:lowercase,ctl:auditLogParts=+E,block,msg:'Cross-site Scripting (XSS) Attack',id:'958016',tag:'WEB_ATTACK/XSS',tag:'WASCTC/WASC-8',tag:'WASCTC/WASC-22',tag:'OWASP_TOP_10/A2',tag:'OWASP_AppSensor/IE1',tag:'PCI/6.5.1',logdata:'% \
//	 	{TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.xss_score=+%{tx.critical_anomaly_score},setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/XSS-%{matched_var_name}=%{tx.0}"
//
// ```
type maturityFn struct{}

func (a *maturityFn) Init(r plugintypes.RuleMetadata, data string) error {
	m, err := strconv.Atoi(data)
	if err != nil {
		return err
	}
	if m < 1 || m > 9 {
		return fmt.Errorf("invalid argument, %d should be between 1 and 9", m)
	}
	r.(*corazawaf.Rule).Maturity_ = m
	return nil
}

func (a *maturityFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *maturityFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeMetadata
}

func maturity() plugintypes.Action {
	return &maturityFn{}
}

var (
	_ plugintypes.Action = &maturityFn{}
	_ ruleActionWrapper  = maturity
)
