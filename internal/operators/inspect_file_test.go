// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package operators

import (
	_ "fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestInspectFile(t *testing.T) {
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
