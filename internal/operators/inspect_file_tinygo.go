// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/rules"
)

type inspectFile struct{}

func newInspectFile(rules.OperatorOptions) (rules.Operator, error) {
	return &unconditionalMatch{}, nil
}

func init() {
	plugins.RegisterOperator("inspectFile", newInspectFile)
}
