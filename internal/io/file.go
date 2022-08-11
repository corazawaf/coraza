package io

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
)

// ReadFirstFile looks for the file in all available paths
// if it fails to find it, it returns an error
func ReadFirstFile(directories []string, filename string) ([]byte, error) {
	if len(filename) == 0 {
		return nil, fmt.Errorf("filename is empty")
	}
	if filename[0] == '/' {
		// filename is absolute
		return ioutil.ReadFile(filename)
	}
	for _, p := range directories {
		f := path.Join(p, filename)
		// if the file does exist we return it
		if _, err := os.Stat(f); err == nil {
			return ioutil.ReadFile(f)
		}
	}
	return nil, fmt.Errorf("file %s not found", filename)
}
