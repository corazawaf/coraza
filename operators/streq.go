// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type streq struct {
	data corazawaf.Macro
}

func (o *streq) Init(options corazawaf.RuleOperatorOptions) error {
	data := options.Arguments

	macro, err := corazawaf.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = *macro
	return nil
}

func (o *streq) Evaluate(tx *corazawaf.Transaction, value string) bool {
	data := o.data.Expand(tx)
	return data == value
}
