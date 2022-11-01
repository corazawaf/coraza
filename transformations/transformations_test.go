// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/buger/jsonparser"
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
		cases := unmarshalTests(t, f)
		for _, data := range cases {
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
				// t.Error(err)
				continue
			}
			out, err := trans(data.Input)
			if err != nil {
				t.Error(err)
			}
			if out != data.Output {
				t.Errorf("Transformation %s:\nInput: %s\nExpected: %v\nGot: %v\nExpected String: %s\nGot String: %s",
					data.Name, data.Input, []byte(data.Output), []byte(out), data.Output, out)
			}
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

func unmarshalTests(t *testing.T, json []byte) []Test {
	t.Helper()
	var err error
	var tests []Test
	_, err = jsonparser.ArrayEach(json, func(value []byte, dataType jsonparser.ValueType, _ int, _ error) {
		test := Test{}
		err = jsonparser.ObjectEach(value, func(key []byte, value []byte, dataType jsonparser.ValueType, _ int) error {
			switch string(key) {
			case "input":
				test.Input, _ = jsonparser.ParseString(value)
			case "output":
				test.Output, _ = jsonparser.ParseString(value)
			case "name":
				test.Name, _ = jsonparser.ParseString(value)
			case "ret":
				test.Ret, err = strconv.Atoi(string(value))
				if err != nil {
					t.Fatal(err)
				}
			case "type":
				test.Type, _ = jsonparser.ParseString(value)
			}

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		tests = append(tests, test)
	})
	if err != nil {
		t.Fatal(err)
	}
	return tests
}
