// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/corazawaf/coraza/v3/internal/io"
)

var errEmptyDirs = errors.New("empty dirs")

func loadFromFile(name string, dirs []string, root fs.FS) ([]byte, error) {
	// io.OSFS takes OS paths, so on Windows a name such as C:\rules\data.txt
	// is absolute too and dirs are joined with OS separators. Every other
	// fs.FS takes slash-separated names. A leading slash stays absolute.
	_, osRoot := root.(io.OSFS)
	if path.IsAbs(name) || (osRoot && filepath.IsAbs(name)) {
		return fs.ReadFile(root, name)
	}

	if len(dirs) == 0 {
		return nil, errEmptyDirs
	}

	join := path.Join
	if osRoot {
		join = filepath.Join
	}

	// handling files by operators is hard because we must know the paths where we can
	// search, for example, the policy path or the binary path...
	// CRS stores the .data files in the same directory as the directives
	var (
		content []byte
		err     error
	)

	for _, p := range dirs {
		absFilepath := join(p, name)
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
