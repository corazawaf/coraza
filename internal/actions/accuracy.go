// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
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
// Specifies the relative accuracy level of the rule related to the number of false positives and false negatives.
// The value is a string based on a numeric scale (1-9 where 9 is extensively tested and 1 is a brand new experimental rule).
//
// Example:
// ```
//
//	SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "\bgetparentfolder\b" \
//		"phase:2,ver:'CRS/2.2.4',accuracy:'9',maturity:'9',capture,t:none,t:htmlEntityDecode,t:compressWhiteSpace,t:lowercase,ctl:auditLogParts=+E,block,msg:'Cross-site Scripting (XSS) Attack',id:'958016',tag:'WEB_ATTACK/XSS',severity:'2'"
//
// ```
type accuracyFn struct{}

func (a *accuracyFn) Init(r plugintypes.RuleMetadata, data string) error {
	acc, err := strconv.Atoi(data)
	if err != nil {
		return fmt.Errorf("invalid accuracy %q: %w", data, err)
	}
	if acc < 1 || acc > 9 {
		return fmt.Errorf("invalid argument, %d should be between 1 and 9", acc)
	}
	r.(*corazawaf.Rule).Accuracy_ = acc
	return nil
}

func (a *accuracyFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *accuracyFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeMetadata
}

func accuracy() plugintypes.Action {
	return &accuracyFn{}
}

var (
	_ plugintypes.Action = &accuracyFn{}
	_ ruleActionWrapper  = accuracy
)
