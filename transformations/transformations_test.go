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

package transformations

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Test struct {
	Input  string `json:"input"`
	Output string `json:"output"`
	Name   string `json:"name"`
	Ret    int    `json:"ret"`
	Type   string `json:"type"`
}

//https://github.com/SpiderLabs/secrules-language-tests/
func TestTransformations(t *testing.T) {
	root := "../testdata/transformations/"
	files := [][]byte{}

	_, err := os.Stat(root)
	require.False(t, os.IsNotExist(err), "failed to find transformation test files")

	err = filepath.Walk(root, func(path string, _ os.FileInfo, _ error) error {
		if strings.HasSuffix(path, ".json") {
			data, _ := ioutil.ReadFile(path)
			files = append(files, data)
		}
		return nil
	})
	require.NoError(t, err, "error walking files")

	for _, f := range files {
		cases := []*Test{}
		err := json.Unmarshal(f, &cases)
		assert.NoError(t, err, "cannot parse test case")

		for _, data := range cases {
			t.Run(data.Name, func(t *testing.T) {
				// UNMARSHALL does not transform \u0000 to binary
				data.Input = strings.ReplaceAll(data.Input, `\u0000`, "\u0000")
				data.Output = strings.ReplaceAll(data.Output, `\u0000`, "\u0000")

				if strings.Contains(data.Input, `\x`) {
					data.Input, _ = strconv.Unquote(`"` + data.Input + `"`)
				}
				if strings.Contains(data.Output, `\x`) {
					data.Output, _ = strconv.Unquote(`"` + data.Output + `"`)
				}
				trans, err := GetTransformation(data.Name)
				if err != nil {
					// TODO(jcchavezs): figure out why error is ignored
					// t.Error(err)
					return
				}
				out, err := trans(data.Input)
				assert.NoError(t, err)
				assert.Equal(t, data.Output, out)
			})
		}
	}
}

func TestTransformationsAreCaseInsensitive(t *testing.T) {
	_, err := GetTransformation("cmdLine")
	require.NoError(t, err)

	_, err = GetTransformation("cmdline")
	require.NoError(t, err)
}
