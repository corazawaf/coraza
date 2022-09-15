// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/rules"
)

type ipMatchFromDataset struct {
	matcher *ipMatch
}

var _ rules.RuleOperator = (*ipMatchFromDataset)(nil)

func (o *ipMatchFromDataset) Init(options rules.RuleOperatorOptions) error {
	data := options.Arguments
	dataset, ok := options.Datasets[data]
	if !ok || len(dataset) == 0 {
		return fmt.Errorf("dataset %q not found", data)
	}

	datasetParsed := strings.Join(dataset, ",")

	o.matcher = &ipMatch{}
	opts := rules.RuleOperatorOptions{
		Arguments: datasetParsed,
	}
	return o.matcher.Init(opts)
}

func (o *ipMatchFromDataset) Evaluate(tx rules.TransactionState, value string) bool {
	return o.matcher.Evaluate(tx, value)
}
