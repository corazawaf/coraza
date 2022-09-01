// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type skipafterFn struct {
	data string
}

func (a *skipafterFn) Init(r *coraza.Rule, data string) error {
	a.data = strings.Trim(data, `"`)
	return nil
}

func (a *skipafterFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	tx.WAF.Logger.Debug("[%s] Starting secmarker %q", tx.ID, a.data)
	tx.SkipAfter = a.data
}

func (a *skipafterFn) Type() types.RuleActionType {
	return types.ActionTypeFlow
}

func skipafter() coraza.RuleAction {
	return &skipafterFn{}
}

var (
	_ coraza.RuleAction = &skipafterFn{}
	_ ruleActionWrapper = skipafter
)
