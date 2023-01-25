// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.pm

package operators

import (
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/rules"
)

type pm struct {
	matcher *regexp.Regexp
}

var _ rules.Operator = (*pm)(nil)

func newPM(options rules.OperatorOptions) (rules.Operator, error) {
	data := options.Arguments

	data = strings.ToLower(data)
	if strings.Contains(data, "|") {
		return &pm{matcher: regexp.MustCompile(data)}, nil
	}
	dict := strings.Split(data, " ")
	patterns := strings.Join(dict[:], "|")
	return &pm{matcher: regexp.MustCompile(patterns)}, nil
}

func (o *pm) Evaluate(tx rules.TransactionState, value string) bool {
	return pmEvaluate(o.matcher, tx, value)
}

func pmEvaluate(matcher *regexp.Regexp, tx rules.TransactionState, value string) bool {
	return matcher.MatchString(value)
}

func init() {
	Register("pm", newPM)
}
