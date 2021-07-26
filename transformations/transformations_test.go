// Copyright 2021 Juan Pablo Tosso
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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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
	root := "../../test/data/transformations/"
	files := [][]byte{}
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".json") {
			data, _ := ioutil.ReadFile(path)
			files = append(files, data)
		}
		return nil
	})
	for _, f := range files {

		cases := []*Test{}
		err := json.Unmarshal(f, &cases)
		if err != nil {
			t.Error("Cannot parse test case")
		}
		for _, data := range cases {
			//UNMARSHALL does not transform \u0000 to binary
			data.Input = strings.ReplaceAll(data.Input, `\u0000`, "\u0000")
			data.Output = strings.ReplaceAll(data.Output, `\u0000`, "\u0000")

			if strings.Contains(data.Input, `\x`) {
				data.Input, _ = strconv.Unquote(`"` + data.Input + `"`)
			}
			if strings.Contains(data.Output, `\x`) {
				data.Output, _ = strconv.Unquote(`"` + data.Output + `"`)
			}
			trans := TransformationsMap()[data.Name]
			if trans == nil {
				//t.Error("Invalid transformation test for " + data.Name)
				continue
			}
			tools := &Tools{}
			out := trans(data.Input, tools)
			if out != data.Output {
				t.Error(fmt.Sprintf("Transformation %s:\nInput: %s\nExpected: %v\nGot: %v\nExpected String: %s\nGot String: %s",
					data.Name, data.Input, []byte(data.Output), []byte(out), data.Output, out))
			}
		}
	}
}
