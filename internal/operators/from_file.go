// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/corazawaf/coraza/v3/internal/io"
)

var errEmptyDirs = errors.New("empty dirs")

func loadFromFile(filename string, dirs []string, root fs.FS) ([]byte, error) {
	if filepath.IsAbs(filename) {
		return io.FSReadFile(root, filename)
	}

	if len(dirs) == 0 {
		return nil, errEmptyDirs
	}

	// handling files by operators is hard because we must know the paths where we can
	// search, for example, the policy path or the binary path...
	// CRS stores the .data files in the same directory as the directives
	var (
		content []byte
		err     error
	)

	for _, p := range dirs {
		absFilepath := filepath.Join(p, filename)
		content, err = io.FSReadFile(root, absFilepath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			} else {
				return nil, err
			}
		}

		return content, nil
	}

	return nil, err
}
