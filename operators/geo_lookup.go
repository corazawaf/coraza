// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3"
)

type geoLookup struct{}

func (o *geoLookup) Init(options coraza.RuleOperatorOptions) error { return nil }

// kept for compatibility, it requires a plugin.
func (o *geoLookup) Evaluate(tx *coraza.Transaction, value string) bool { return true }

var _ coraza.RuleOperator = &geoLookup{}
