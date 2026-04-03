// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.disabled_operators.inspectFile

package operators

import (
	"context"
	"os/exec"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Executes an external program for every variable in the target list. Useful for integrating
// external validation tools (virus scanners, content analyzers, etc.). The program receives
// the variable value as a command-line argument and has a 10-second timeout.
//
// Arguments:
// Path to the external program/script to execute. The program should return '1' in the first
// byte of output to indicate a match, any other output indicates no match.
//
// Returns:
// true if the external program indicates a match (non-'1' output), false on timeout or '1' output
//
// Example:
// ```
// # Scan uploaded files with external antivirus
// SecRule FILES_TMPNAMES "@inspectFile /usr/local/bin/av-scan.sh" "id:203,deny,log,msg:'Virus detected'"
//
// # Custom content validation script
// SecRule REQUEST_BODY "@inspectFile /opt/waf/scripts/validate-content.py" "id:204,deny"
// ```
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
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded || err != nil {
		return false
	}
	return len(output) > 0 && output[0] != '1'
}

func init() {
	Register("inspectFile", newInspectFile)
}
