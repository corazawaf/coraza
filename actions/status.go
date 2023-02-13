// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type statusFn struct{}

func (a *statusFn) Init(r rules.RuleMetadata, data string) error {
	status, err := strconv.Atoi(data)
	if err != nil {
		return err
	}
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).DisruptiveStatus = status
	return nil
}

func (a *statusFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {}

func (a *statusFn) Type() rules.ActionType {
	return rules.ActionTypeData
}

func status() rules.Action {
	return &statusFn{}
}

var (
	_ rules.Action      = &statusFn{}
	_ ruleActionWrapper = status
)
