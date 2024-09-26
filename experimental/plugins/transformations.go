// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/redwanghb/coraza/v3/experimental/plugins/plugintypes"
	"github.com/redwanghb/coraza/v3/internal/transformations"
)

// RegisterTransformation registers a transformation by name
// If the transformation is already registered, it will be overwritten
func RegisterTransformation(name string, trans plugintypes.Transformation) {
	transformations.Register(name, trans)
}
