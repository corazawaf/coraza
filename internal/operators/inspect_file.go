// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.disabled_operators.inspectFile
// +build !tinygo,!coraza.disabled_operators.inspectFile

package operators

import (
	"context"
	"os/exec"
	"time"

	"github.com/corazawaf/coraza/v3/operators"
	"github.com/corazawaf/coraza/v3/rules"
)

type inspectFile struct {
	path string
}

var _ rules.Operator = (*inspectFile)(nil)

func newInspectFile(options rules.OperatorOptions) (rules.Operator, error) {
	return &inspectFile{path: options.Arguments}, nil
}

func (o *inspectFile) Evaluate(tx rules.TransactionState, value string) bool {
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

func init() {
	operators.Register("inspectFile", newInspectFile)
}
