// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

type ipMatchFromFile struct {
	ipMatcher *ipMatch
}

func (o *ipMatchFromFile) Init(options coraza.RuleOperatorOptions) error {
	path := options.Arguments

	data, err := loadFromFile(path, options.Path)
	if err != nil {
		return err
	}

	dataParsed := strings.Builder{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		l := sc.Text()
		l = strings.TrimSpace(l)
		if len(l) == 0 {
			continue
		}
		if l[0] == '#' {
			continue
		}
		dataParsed.WriteString(",")
		dataParsed.WriteString(l)
	}

	o.ipMatcher = &ipMatch{}
	opts := coraza.RuleOperatorOptions{
		Arguments: dataParsed.String(),
	}
	return o.ipMatcher.Init(opts)
}

func (o *ipMatchFromFile) Evaluate(tx *coraza.Transaction, value string) bool {
	return o.ipMatcher.Evaluate(tx, value)
}

var _ coraza.RuleOperator = (*ipMatchFromFile)(nil)
