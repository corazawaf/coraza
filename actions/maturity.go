// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type maturityFn struct {
}

func (a *maturityFn) Init(r *coraza.Rule, data string) error {
	m, err := strconv.Atoi(data)
	if err != nil {
		return err
	}
	if m < 1 || m > 9 {
		return fmt.Errorf("maturity must be between 1 and 9, not %d", m)
	}
	r.Maturity = m
	return nil
}

func (a *maturityFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not evaluated
}

func (a *maturityFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func maturity() coraza.RuleAction {
	return &maturityFn{}
}

var (
	_ coraza.RuleAction = &maturityFn{}
	_ ruleActionWrapper = maturity
)
