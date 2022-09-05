// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"strconv"
)

type gt struct {
	data corazawaf.Macro
}

func (o *gt) Init(options corazawaf.RuleOperatorOptions) error {
	data := options.Arguments

	macro, err := corazawaf.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = *macro
	return nil
}

func (o *gt) Evaluate(tx *corazawaf.Transaction, value string) bool {
	v, _ := strconv.Atoi(value)
	k, _ := strconv.Atoi(o.data.Expand(tx))
	return k < v
}
