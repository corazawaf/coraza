// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type maturityFn struct {
}

func (a *maturityFn) Init(r *corazawaf.Rule, data string) error {
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

func (a *maturityFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// Not evaluated
}

func (a *maturityFn) Type() types.RuleActionType {
	return types.ActionTypeMetadata
}

func maturity() corazawaf.RuleAction {
	return &maturityFn{}
}

var (
	_ corazawaf.RuleAction = &maturityFn{}
	_ ruleActionWrapper    = maturity
)
