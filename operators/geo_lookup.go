// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type geoLookup struct{}

var _ corazawaf.RuleOperator = (*geoLookup)(nil)

func (*geoLookup) Init(corazawaf.RuleOperatorOptions) error { return nil }

// kept for compatibility, it requires a plugin.
func (*geoLookup) Evaluate(*corazawaf.Transaction, string) bool { return true }
