// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type noMatch struct{}

var _ corazawaf.RuleOperator = (*noMatch)(nil)

func (*noMatch) Init(options corazawaf.RuleOperatorOptions) error { return nil }

func (*noMatch) Evaluate(tx *corazawaf.Transaction, value string) bool { return false }
