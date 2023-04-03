// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/transformations"
	"github.com/corazawaf/coraza/v3/rules"
)

type tFn struct{}

func (a *tFn) Init(r rules.RuleMetadata, data string) error {
	// TODO there is a chance that it won't work, it requires tests
	// none is a special hardcoded transformation, it must remove previous transformations
	if data == "none" {
		// remove elements
		r.(*corazawaf.Rule).ClearTransformations()
		return nil
	}

	tt, err := transformations.GetTransformation(data)
	if err != nil {
		return err
	}
	return r.(*corazawaf.Rule).AddTransformation(data, tt)
}

func (a *tFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {}

func (a *tFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func t() rules.Action {
	return &tFn{}
}

var (
	_ rules.Action      = &tFn{}
	_ ruleActionWrapper = t
)
