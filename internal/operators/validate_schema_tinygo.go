// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo && !coraza.disabled_operators.validateSchema
// +build tinygo,!coraza.disabled_operators.validateSchema

package operators

import "github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"


// NewValidateSchema is not implemented in TinyGo and falls back to an unconditional match.
func NewValidateSchema(_ plugintypes.OperatorOptions) (plugintypes.Operator, error) {
   return &unconditionalMatch{}, nil
}


func init() {
   Register("validateSchema", NewValidateSchema)
}
