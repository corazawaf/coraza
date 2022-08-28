// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"bufio"
	"strings"

	"github.com/corazawaf/coraza/v3"
	engine "github.com/corazawaf/coraza/v3"
)

type ipMatchFromFile struct {
	ip *ipMatch
}

func (o *ipMatchFromFile) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments

	dataParsed := ""
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		l := sc.Text()
		l = strings.TrimSpace(l)
		if len(l) == 0 {
			continue
		}
		if l[0] == '#' {
			continue
		}
		dataParsed += ","
		dataParsed += l
	}

	o.ip = &ipMatch{}
	opts := coraza.RuleOperatorOptions{
		Arguments: dataParsed,
	}
	return o.ip.Init(opts)
}

func (o *ipMatchFromFile) Evaluate(tx *engine.Transaction, value string) bool {
	return o.ip.Evaluate(tx, value)
}

var _ coraza.RuleOperator = (*ipMatchFromFile)(nil)
