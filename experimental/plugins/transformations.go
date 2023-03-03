// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
package plugins

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/rules"
)

var transformationsMap = map[string]rules.Transformation{}

// RegisterTransformation registers a transformation by name
// If the transformation is already registered, it will be overwritten
func RegisterTransformation(name string, trans rules.Transformation) {
	transformationsMap[strings.ToLower(name)] = trans
}

// GetTransformation returns a transformation by name
// If the transformation is not found, it returns an error
func GetTransformation(name string) (rules.Transformation, error) {
	if t, ok := transformationsMap[strings.ToLower(name)]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("invalid transformation name %q", name)
}
