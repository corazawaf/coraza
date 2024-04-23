// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !no_fs_access
// +build !no_fs_access

package environment

import (
	"fmt"
	"os"
)

// HasAccessToFS indicates whether the runtime target environment has access
// to OS' filesystem or not.
var HasAccessToFS = true

// IsDirWritable is a helper function to check if the WAF has access to the filesystem
func IsDirWritable(dir string) error {
	file, err := os.CreateTemp(dir, "checkfsfile")
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer func() {
		file.Close()
		os.Remove(file.Name())
	}()
	return nil
}
