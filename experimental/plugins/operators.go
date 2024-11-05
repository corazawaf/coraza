// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/operators"
)

// RegisterOperator registers a new operator
// If the operator already exists it will be overwritten
func RegisterOperator(name string, op plugintypes.OperatorFactory) {
	operators.Register(name, op)
}
