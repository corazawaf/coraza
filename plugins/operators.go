// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
package plugins

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/rules"
)

var operatorsMap = map[string]rules.OperatorFactory{}

// GetOperator returns an operator by name
func GetOperator(name string, options rules.OperatorOptions) (rules.Operator, error) {
	if op, ok := operatorsMap[name]; ok {
		return op(options)
	}
	return nil, fmt.Errorf("operator %s not found", name)
}

// RegisterOperator registers a new operator
// If the operator already exists it will be overwritten
func RegisterOperator(name string, op rules.OperatorFactory) {
	operatorsMap[name] = op
}
