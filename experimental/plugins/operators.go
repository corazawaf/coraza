// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/redwanghb/coraza/v3/experimental/plugins/plugintypes"
	"github.com/redwanghb/coraza/v3/internal/operators"
)

// RegisterOperator registers a new operator
// If the operator already exists it will be overwritten
func RegisterOperator(name string, op plugintypes.OperatorFactory) {
	operators.Register(name, op)
}
