// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type statusFn struct {
}

func (a *statusFn) Init(r *corazawaf.Rule, b1 string) error {
	status, err := strconv.Atoi(b1)
	if err != nil {
		return err
	}
	r.DisruptiveStatus = status
	return nil
}

func (a *statusFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
}

func (a *statusFn) Type() types.RuleActionType {
	return types.ActionTypeData
}

func status() corazawaf.RuleAction {
	return &statusFn{}
}

var (
	_ corazawaf.RuleAction = &statusFn{}
	_ ruleActionWrapper    = status
)
