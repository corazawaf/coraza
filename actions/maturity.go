// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type maturityFn struct {
}

func (a *maturityFn) Init(r rules.RuleMetadata, data string) error {
	m, err := strconv.Atoi(data)
	if err != nil {
		return err
	}
	if m < 1 || m > 9 {
		return fmt.Errorf("maturity must be between 1 and 9, not %d", m)
	}
	// TODO(anuraaga): Confirm this is internal implementation detail
	r.(*corazawaf.Rule).Maturity = m
	return nil
}

func (a *maturityFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	// Not evaluated
}

func (a *maturityFn) Type() rules.ActionType {
	return rules.ActionTypeMetadata
}

func maturity() rules.Action {
	return &maturityFn{}
}

var (
	_ rules.Action      = &maturityFn{}
	_ ruleActionWrapper = maturity
)
