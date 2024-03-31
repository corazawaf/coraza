// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package environment

import (
	"fmt"
	"os"

	"github.com/corazawaf/coraza/v3/debuglog"
)

// CheckFSAccess is a helper function to check if the WAF has access to the filesystem
func CheckFSAccess(logger debuglog.Logger, tmpDir string) error {
	if HasAccessToFS {
		file, err := os.CreateTemp(tmpDir, "checkfsfile")
		if err != nil {
			return fmt.Errorf("create file: %w", err)
		}
		defer file.Close()

		_, err = file.WriteString("check fs data")
		if err != nil {
			return fmt.Errorf("write to file: %w", err)
		}

		err = os.Remove(file.Name())
		if err != nil {
			return fmt.Errorf("remove file: %w", err)
		}
		logger.Debug().Msg("Filesystem access check successful")
		return nil
	}
	logger.Debug().Msg("Filesystem access check skipped")
	return nil
}
