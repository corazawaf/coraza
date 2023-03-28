// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/corazawaf/coraza/v3/internal/operators"
	"github.com/corazawaf/coraza/v3/rules"
)

// RegisterOperator registers a new operator
// If the operator already exists it will be overwritten
func RegisterOperator(name string, op rules.OperatorFactory) {
	operators.Register(name, op)
}
