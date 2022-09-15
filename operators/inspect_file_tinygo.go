// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type inspectFile struct{}

func (*inspectFile) Init(rules.OperatorOptions) error { return nil }

func (*inspectFile) Evaluate(*corazawaf.Transaction, string) bool { return true }
