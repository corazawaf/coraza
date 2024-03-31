// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package environment

import (
	"os"
	"testing"

	"github.com/corazawaf/coraza/v3/debuglog"
)

func TestFSCheck(t *testing.T) {
	testCases := []struct {
		name          string
		hasAccessToFS bool
		tmpDir        string
		expectError   bool
	}{
		{
			name:          "No access to FS",
			hasAccessToFS: false,
			expectError:   false,
		},
		{
			name:          "Has access to FS, non-existent dir",
			hasAccessToFS: true,
			tmpDir:        "/non-existent-dir",
			expectError:   true,
		},
		{
			name:          "Has access to FS, existent dir",
			hasAccessToFS: true,
			tmpDir:        os.TempDir(),
			expectError:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("TMPDIR", tc.tmpDir)
			HasAccessToFS = tc.hasAccessToFS
			err := CheckFSAccess(debuglog.Default(), tc.tmpDir)
			if tc.expectError && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
