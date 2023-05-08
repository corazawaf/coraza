// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

type Test struct {
	Input  string
	Output string
	Name   string
	Ret    int
	Type   string
}

// https://github.com/SpiderLabs/secrules-language-tests/
func TestTransformations(t *testing.T) {
	root := "./testdata"
	var files [][]byte
	if _, err := os.Stat(root); os.IsNotExist(err) {
		t.Error("failed to find transformation test files")
	}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".json") {
			data, _ := os.ReadFile(path)
			files = append(files, data)
		}
		return nil
	}); err != nil {
		t.Error("Error walking files")
	}
	for _, f := range files {
		cases := unmarshalTests(f)
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
					// Cannot use t.Skip for TinyGo support
					return
				}
				out, _, err := trans(data.Input)
				if err != nil {
					t.Error(err)
				}
				if out != data.Output {
					t.Errorf("Transformation %s:\nInput: %s\nExpected: %v\nGot: %v\nExpected String: %s\nGot String: %s",
						data.Name, data.Input, []byte(data.Output), []byte(out), data.Output, out)
				}
			})
		}
	}
}

func TestTransformationsAreCaseInsensitive(t *testing.T) {
	if _, err := GetTransformation("cmdLine"); err != nil {
		t.Error(err)
	}
	if _, err := GetTransformation("cmdline"); err != nil {
		t.Error(err)
	}
}

func unmarshalTests(json []byte) []Test {
	var tests []Test
	v := gjson.ParseBytes(json).Value()
	for _, in := range v.([]interface{}) {
		obj := in.(map[string]interface{})
		t := Test{}
		if s, ok := obj["input"]; ok {
			t.Input = s.(string)
		}
		if s, ok := obj["output"]; ok {
			t.Output = s.(string)
		}
		if s, ok := obj["name"]; ok {
			t.Name = s.(string)
		}
		if s, ok := obj["ret"]; ok {
			t.Ret = int(s.(float64))
		}
		if s, ok := obj["type"]; ok {
			t.Type = s.(string)
		}
		tests = append(tests, t)
	}
	return tests
}
