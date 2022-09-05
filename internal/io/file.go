// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package io

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

// ReadFirstFile looks for the file in all available paths
// if it fails to find it, it returns an error
func ReadFirstFile(directories []string, filename string) ([]byte, error) {
	if len(filename) == 0 {
		return nil, fmt.Errorf("filename is empty")
	}
	if filename[0] == '/' {
		// filename is absolute
		return os.ReadFile(filename)
	}
	for _, p := range directories {
		f := path.Join(p, filename)
		// if the file does exist we return it
		if _, err := os.Stat(f); err == nil {
			return os.ReadFile(f)
		}
	}
	return nil, fmt.Errorf("file %s not found", filename)
}

// OSFS implements fs.FS using methods on os to read from the system.
// Note that this implementation is not a compliant fs.FS, as they should only
// accept posix-style, relative paths, but as this is an internal implementation
// detail, we get the abstraction we need while being able to handle paths as
// the os package otherwise would.
// More context in: https://github.com/golang/go/issues/44279
type OSFS struct{}

func (OSFS) Open(name string) (fs.File, error) {
	return os.Open(name)
}

func (OSFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (OSFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return os.ReadDir(name)
}

func (OSFS) Glob(pattern string) ([]string, error) {
	return filepath.Glob(pattern)
}
