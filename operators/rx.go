// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"regexp"

	"github.com/corazawaf/coraza/v3/rules"
)

type rx struct {
	re *regexp.Regexp
}

var _ rules.Operator = (*rx)(nil)

func (o *rx) Init(options rules.OperatorOptions) error {
	data := options.Arguments

	re, err := regexp.Compile(data)
	o.re = re
	return err
}

func (o *rx) Evaluate(tx rules.TransactionState, value string) bool {
	match := o.re.FindStringSubmatch(value)
	if len(match) == 0 {
		return false
	}

	if tx.Capturing() {
		for i, c := range match {
			if i == 9 {
				return true
			}
			tx.CaptureField(i, c)
		}
	}

	return true
}
