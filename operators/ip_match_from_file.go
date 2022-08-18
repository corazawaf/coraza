// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3"
	engine "github.com/corazawaf/coraza/v3"
)

type ipMatchFromFile struct {
	ip *ipMatch
}

func (o *ipMatchFromFile) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments

	o.ip = &ipMatch{}
	subnets := strings.ReplaceAll(data, "\n", ",")
	opts := coraza.RuleOperatorOptions{
		Arguments: subnets,
	}
	return o.ip.Init(opts)
}

func (o *ipMatchFromFile) Evaluate(tx *engine.Transaction, value string) bool {
	return o.ip.Evaluate(tx, value)
}
