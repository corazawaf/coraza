// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/corazawaf/coraza/v3/internal/transformations"
	"github.com/corazawaf/coraza/v3/rules"
)

// RegisterTransformation registers a transformation by name
// If the transformation is already registered, it will be overwritten
func RegisterTransformation(name string, trans rules.Transformation) {
	transformations.Register(name, trans)
}
