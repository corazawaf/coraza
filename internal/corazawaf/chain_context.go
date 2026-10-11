// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import "github.com/corazawaf/coraza/v3/types"

var captureKeys = [10]string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}

// chainContext is what a chained rule can observe from one match of the rule
// before it.
type chainContext struct {
	match          types.MatchData
	matchedVar     string
	matchedVarName string
	captures       [10]string
}

func newChainContext(tx *Transaction, match types.MatchData) chainContext {
	c := chainContext{
		match:          match,
		matchedVar:     tx.variables.matchedVar.Get(),
		matchedVarName: tx.variables.matchedVarName.Get(),
	}
	for i, k := range captureKeys {
		if v := tx.variables.tx.Get(k); len(v) > 0 {
			c.captures[i] = v[0]
		}
	}
	return c
}

func (c chainContext) restore(tx *Transaction) {
	tx.variables.matchedVar.Set(c.matchedVar)
	tx.variables.matchedVarName.Set(c.matchedVarName)
	for i, k := range captureKeys {
		tx.variables.tx.SetIndex(k, 0, c.captures[i])
	}
}
