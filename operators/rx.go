// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"regexp"

	"github.com/corazawaf/coraza/v3"
)

type rx struct {
	re *regexp.Regexp
}

var _ coraza.RuleOperator = (*rx)(nil)

func (o *rx) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments

	re, err := regexp.Compile(data)
	o.re = re
	return err
}

func (o *rx) Evaluate(tx *coraza.Transaction, value string) bool {
	match := o.re.FindStringSubmatch(value)
	lcount := len(match)
	if lcount == 0 {
		return false
	}

	if tx.Capture {
		for i, c := range match {
			if i == 9 {
				return true
			}
			tx.CaptureField(i, c)
		}
	}

	return true
}
