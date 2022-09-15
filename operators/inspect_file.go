// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package operators

import (
	"context"
	"os/exec"
	"time"

	"github.com/corazawaf/coraza/v3"
)

type inspectFile struct {
	path string
}

var _ coraza.RuleOperator = (*inspectFile)(nil)

func (o *inspectFile) Init(options coraza.RuleOperatorOptions) error {
	o.path = options.Arguments
	return nil
}

func (o *inspectFile) Evaluate(tx *coraza.Transaction, value string) bool {
	// TODO parametrize timeout
	// TODO add relative path capabilities
	// TODO add lua special support
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Add /bin/bash to context?
	cmd := exec.CommandContext(ctx, o.path, value)
	_, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded || err != nil {
		return false
	}
	return true
}
