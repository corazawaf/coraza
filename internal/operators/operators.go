// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

var operators = map[string]plugintypes.OperatorFactory{}

// Get returns an operator by name
func Get(name string, options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	if op, ok := operators[name]; ok {
		return op(options)
	}
	return nil, fmt.Errorf("operator %s not found", name)
}

// Register registers a new operator
// If the operator already exists it will be overwritten
func Register(name string, op plugintypes.OperatorFactory) {
	operators[name] = op
}
