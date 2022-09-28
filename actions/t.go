// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
	transformations "github.com/corazawaf/coraza/v3/transformations"
)

type tFn struct{}

func (a *tFn) Init(r rules.RuleMetadata, input string) error {
	// TODO there is a chance that it won't work, it requires tests
	// none is a special hardcoded transformation, it must remove previous transformations
	if input == "none" {
		// remove elements
		// TODO(anuraaga): Confirm this is internal implementation detail
		r.(*corazawaf.Rule).ClearTransformations()
		return nil
	}
	tt, err := transformations.GetTransformation(input)
	if err != nil {
		return err
	}
	return r.(*corazawaf.Rule).AddTransformation(input, tt)
}

func (a *tFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	// Not evaluated
}

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
