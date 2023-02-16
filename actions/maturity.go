// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type maturityFn struct{}

func (a *maturityFn) Init(r rules.RuleMetadata, data string) error {
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

func (a *maturityFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {}

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
