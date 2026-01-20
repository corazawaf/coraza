// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package operators

import (
	_ "fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestInspectFileExitCode(t *testing.T) {
	existCommand := "/bin/echo"
	if runtime.GOOS == "windows" {
		existCommand = "C:\\Windows\\system32\\tasklist.exe"
	}

	tests := []struct {
		path   string
		exists bool
	}{
		{
			path:   existCommand,
			exists: true,
		},
		{
			path:   filepath.Join(t.TempDir(), "nonexistent.txt"),
			exists: false,
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.path, func(t *testing.T) {
			ipf, err := newInspectFile(plugintypes.OperatorOptions{Arguments: tt.path})
			if err != nil {
				t.Error("cannot init inspectfile operator")
			}
			if want, have := tt.exists, ipf.Evaluate(nil, "/?"); want != have {
				t.Errorf("inspectfile path %s: want %v, have %v", tt.path, want, have)
			}
		})
	}
}

func TestInspectFileOutput(t *testing.T) {
	existCommand := "/bin/echo"
	if runtime.GOOS == "windows" {
		// TODO: Add support for this platform.
		t.Skip("Skipping test on Windows")
	}

	ipf, err := newInspectFile(plugintypes.OperatorOptions{Arguments: existCommand})
	if err != nil {
		t.Error("cannot init inspectfile operator")
	}

	tests := []struct {
		output string
		match  bool
	}{
		{
			output: "1 clamscan: OK",
			match:  false,
		},
		{
			output: "0 clamscan: FOUND",
			match:  true,
		},
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt.output, func(t *testing.T) {
			if want, have := tt.match, ipf.Evaluate(nil, tt.output); want != have {
				t.Errorf("inspectfile output '%s': want %t, have %t", tt.output, want, have)
			}
		})
	}
}
