// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package operators

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type rbl struct{}

func (o *rbl) Init(_ rules.OperatorOptions) error { return nil }

func (o *rbl) Evaluate(_ *corazawaf.Transaction, _ string) bool { return true }
