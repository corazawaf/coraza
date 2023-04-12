// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.disabled_operators.inspectFile
// +build !tinygo,!coraza.disabled_operators.inspectFile

package operators

import (
	"context"
	"os/exec"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type inspectFile struct {
	path string
}

var _ plugintypes.Operator = (*inspectFile)(nil)

func newInspectFile(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &inspectFile{path: options.Arguments}, nil
}

func (o *inspectFile) Evaluate(tx plugintypes.TransactionState, value string) bool {
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
	Register("inspectFile", newInspectFile)
}
