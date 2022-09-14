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

package operators

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v2"
)

type Test struct {
	Input string `json:"input"`
	Param string `json:"param"`
	Name  string `json:"name"`
	Ret   int    `json:"ret"`
	Type  string `json:"type"`
}

// https://github.com/SpiderLabs/secrules-language-tests/
func TestTransformations(t *testing.T) {
	root := "../testdata/operators/"
	files := map[string][]byte{}
	if _, err := os.Stat(root); os.IsNotExist(err) {
		t.Error("failed to find operator test files")
	}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".json") {
			data, _ := os.ReadFile(path)
			files[path] = data
		}
		return nil
	}); err != nil {
		t.Error("failed to walk test files")
	}
	waf := coraza.NewWaf()
	for name, f := range files {
		t.Run(name, func(t *testing.T) {
			cases := []*Test{}
			err := json.Unmarshal(f, &cases)
			if err != nil {
				t.Error("Cannot parse test case", err)
			}
			for _, data := range cases {
				// UNMARSHALL does not transform \u0000 to binary
				data.Input = strings.ReplaceAll(data.Input, `\u0000`, "\u0000")
				data.Param = strings.ReplaceAll(data.Param, `\u0000`, "\u0000")

				if strings.Contains(data.Input, `\x`) {
					data.Input, err = strconv.Unquote(`"` + data.Input + `"`)
					if err != nil {
						t.Errorf("Cannot parse test case: %v", err)
					}
				}
				if strings.Contains(data.Param, `\x`) {
					data.Param, err = strconv.Unquote(`"` + data.Param + `"`)
					if err != nil {
						t.Errorf("Cannot parse test case: %v", err)
					}
				}
				op, err := GetOperator(data.Name)
				if err != nil {
					continue
				}
				if data.Name == "pmFromFile" || data.Name == "ipMatchFromFile" {
					// read file
					fname := root + "op/" + data.Param
					d, err := os.ReadFile(fname)
					if err != nil {
						t.Errorf("Cannot open file %q", data.Param)
					}
					data.Param = string(d)
				}
				if err := op.Init(data.Param); err != nil {
					t.Errorf("failed to init: %v", err)
				}
				res := op.Evaluate(waf.NewTransaction(), data.Input)
				// 1 = expected true
				// 0 = expected false
				if (res && data.Ret != 1) || (!res && data.Ret == 1) {
					expected := "match"
					if data.Ret == 0 {
						expected = "no match"
					}
					t.Errorf("Invalid operator result for @%s(%q, %q), %s expected", data.Name, data.Param, data.Input, expected)
				}
			}
		})
	}

}
