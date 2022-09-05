// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	transformations "github.com/corazawaf/coraza/v3/transformations"
	"github.com/corazawaf/coraza/v3/types"
)

type tFn struct{}

func (a *tFn) Init(r *corazawaf.Rule, input string) error {
	// TODO there is a chance that it won't work, it requires tests
	// none is a special hardcoded transformation, it must remove previous transformations
	if input == "none" {
		// remove elements
		r.ClearTransformations()
		return nil
	}
	tt, err := transformations.GetTransformation(input)
	if err != nil {
		return err
	}
	return r.AddTransformation(input, tt)
}

func (a *tFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// Not evaluated
}

func (a *tFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func t() corazawaf.RuleAction {
	return &tFn{}
}

var (
	_ corazawaf.RuleAction = &tFn{}
	_ ruleActionWrapper    = t
)
