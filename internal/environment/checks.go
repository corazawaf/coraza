// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package environment

import (
	"fmt"
	"os"

	"github.com/corazawaf/coraza/v3/debuglog"
)

// IsDirWritable is a helper function to check if the WAF has access to the filesystem
func IsDirWritable(logger debuglog.Logger, dir string) error {
	if !HasAccessToFS {
		logger.Debug().Msg("Filesystem access check skipped")
		return nil
	}
	file, err := os.CreateTemp(dir, "checkfsfile")
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer func() {
		file.Close()
		os.Remove(file.Name())
	}()
	logger.Debug().Msg("Filesystem access check successful")
	return nil
}
