// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
