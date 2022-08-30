// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"errors"
	"os"
	"path"
)

func loadFromFile(filepath string, paths []string) ([]byte, error) {
	if path.IsAbs(filepath) {
		return os.ReadFile(filepath)
	}

	// handling files by operators is hard because we must know the paths where we can
	// search, for example, the policy path or the binary path...
	// CRS stores the .data files in the same directory as the directives
	var (
		content []byte
		err     error
	)

	for _, p := range paths {
		if p == "" {
			continue
		}

		absFilepath := path.Join(p, filepath)
		content, err = os.ReadFile(absFilepath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			} else {
				return nil, err
			}
		}

		return content, nil
	}

	return nil, err
}
