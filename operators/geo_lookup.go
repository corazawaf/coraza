// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3/rules"
)

type geoLookup struct{}

var _ rules.RuleOperator = (*geoLookup)(nil)

func (*geoLookup) Init(rules.RuleOperatorOptions) error { return nil }

// kept for compatibility, it requires a plugin.
func (*geoLookup) Evaluate(rules.TransactionState, string) bool { return true }
