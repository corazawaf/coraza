// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import "github.com/corazawaf/coraza/v3/types"

type Rule interface {
	Evaluate(state TransactionState) []types.MatchData
}

type RuleInfo interface {
	GetID() int
	GetParentID() int
	Status() int
}
