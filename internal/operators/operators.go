// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package operators implements SecLang rule operators for matching and validation.
//
// Operators are functions that evaluate input data and return true or false.
// They are used in SecRule directives with the syntax: @operatorName argument
//
// Example:
//
//	SecRule ARGS "@contains evil" "id:100,deny"
//
// Operators can be negated using the ! prefix:
//
//	SecRule REQUEST_LINE "!@beginsWith GET" "id:101,deny"
//
// For the complete list of available operators, see: https://coraza.io/docs/seclang/operators/
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
