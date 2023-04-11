// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/tidwall/gjson"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
)

type Test struct {
	Input string
	Param string
	Name  string
	Ret   int
	Type  string
}

// https://github.com/SpiderLabs/secrules-language-tests/
func TestOperators(t *testing.T) {
	root := "./testdata"
	var files [][]byte
	if _, err := os.Stat(root); os.IsNotExist(err) {
		t.Fatal("failed to find operator test files")
	}

	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".json") {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files = append(files, data)
		}
		return nil
	}); err != nil {
		t.Fatalf("failed to walk test files: %s", err.Error())
	}

	notImplemented := []string{
		"containsWord",
		"strmatch",
		"verifyCC",
		"verifycpf",
		"verifyssn",
		"verifysvnr",
	}

	captureMatrix := map[string]bool{
		"with capture":    true,
		"without capture": false,
	}

	waf := corazawaf.NewWAF()
	for _, f := range files {
		cases := unmarshalTests(t, f)
		for _, data := range cases {
			if utils.InSlice("containsWord", notImplemented) {
				continue
			}
			for capName, capVal := range captureMatrix {
				t.Run(data.Name+" "+capName, func(t *testing.T) {
					// UNMARSHALL does not transform \u0000 to binary
					data.Input = strings.ReplaceAll(data.Input, `\u0000`, "\u0000")
					data.Param = strings.ReplaceAll(data.Param, `\u0000`, "\u0000")

					if strings.Contains(data.Input, `\x`) {
						in, err := strconv.Unquote(`"` + data.Input + `"`)
						if err != nil {
							t.Errorf("Cannot parse test case: %s", err.Error())
						} else {
							data.Input = in
						}
					}

					if strings.Contains(data.Param, `\x`) {
						p, err := strconv.Unquote(`"` + data.Param + `"`)
						if err != nil {
							t.Errorf("Cannot parse test case: %s", err.Error())
						}
						data.Param = p
					}

					opts := plugintypes.OperatorOptions{
						Arguments: data.Param,
						Path:      []string{"op"},
						Root:      os.DirFS("testdata"),
					}
					op, err := Get(data.Name, opts)
					if err != nil {
						t.Error(err)
						return
					}
					tx := waf.NewTransaction()
					tx.Capture = capVal
					res := op.Evaluate(tx, data.Input)
					// 1 = expected true
					// 0 = expected false
					if (res && data.Ret != 1) || (!res && data.Ret == 1) {
						expected := "match"
						if data.Ret == 0 {
							expected = "no match"
						}
						t.Errorf("Invalid operator result for @%s(%q, %q), %s expected", data.Name, data.Param, data.Input, expected)
					}
				})
			}
		}
	}
}

func unmarshalTests(t *testing.T, json []byte) []Test {
	t.Helper()
	var tests []Test
	v := gjson.ParseBytes(json).Value()
	for _, in := range v.([]interface{}) {
		obj := in.(map[string]interface{})
		t := Test{}
		if s, ok := obj["input"]; ok {
			t.Input = s.(string)
		}
		if s, ok := obj["param"]; ok {
			t.Param = s.(string)
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
