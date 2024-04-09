// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !no_fs_access
// +build !no_fs_access

package environment

import (
	"os"
	"testing"
)

func TestFSCheck(t *testing.T) {
	testCases := []struct {
		name          string
		hasAccessToFS bool
		tmpDir        string
		expectError   bool
	}{
		{
			name:        "Has access to FS, non-existent dir",
			tmpDir:      "/non-existent-dir",
			expectError: true,
		},
		{
			name:        "Has access to FS, existent dir",
			tmpDir:      os.TempDir(),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("TMPDIR", tc.tmpDir)
			err := IsDirWritable(tc.tmpDir)
			if tc.expectError && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
