// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"errors"
	"io/fs"
	"os"
	"path"
)

var errEmptyPaths = errors.New("empty paths")

func loadFromFile(filepath string, paths []string, root fs.FS) ([]byte, error) {
	if path.IsAbs(filepath) {
		return fs.ReadFile(root, filepath)
	}

	if len(paths) == 0 {
		return nil, errEmptyPaths
	}

	// handling files by operators is hard because we must know the paths where we can
	// search, for example, the policy path or the binary path...
	// CRS stores the .data files in the same directory as the directives
	var (
		content []byte
		err     error
	)

	for _, p := range paths {
		absFilepath := path.Join(p, filepath)
		content, err = fs.ReadFile(root, absFilepath)
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
