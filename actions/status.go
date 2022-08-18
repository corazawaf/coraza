// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"strconv"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type statusFn struct {
}

func (a *statusFn) Init(r *coraza.Rule, b1 string) error {
	status, err := strconv.Atoi(b1)
	if err != nil {
		return err
	}
	r.DisruptiveStatus = status
	return nil
}

func (a *statusFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
}

func (a *statusFn) Type() types.RuleActionType {
	return types.ActionTypeData
}

func status() coraza.RuleAction {
	return &statusFn{}
}

var (
	_ coraza.RuleAction = &statusFn{}
	_ ruleActionWrapper = status
)
