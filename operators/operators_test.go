// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/tidwall/gjson"
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
	files := [][]byte{}
	if _, err := os.Stat(root); os.IsNotExist(err) {
		t.Error("failed to find operator test files")
	}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".json") {
			data, _ := os.ReadFile(path)
			files = append(files, data)
		}
		return nil
	}); err != nil {
		t.Error("failed to walk test files")
	}
	waf := coraza.NewWaf()
	for _, f := range files {
		cases := unmarshalTests(t, f)
		for _, data := range cases {
			t.Run(data.Name, func(t *testing.T) {
				// UNMARSHALL does not transform \u0000 to binary
				data.Input = strings.ReplaceAll(data.Input, `\u0000`, "\u0000")
				data.Param = strings.ReplaceAll(data.Param, `\u0000`, "\u0000")

				if strings.Contains(data.Input, `\x`) {
					in, err := strconv.Unquote(`"` + data.Input + `"`)
					if err != nil {
						t.Error("Cannot parse test case", err)
					} else {
						data.Input = in
					}
				}
				if strings.Contains(data.Param, `\x`) {
					p, err := strconv.Unquote(`"` + data.Param + `"`)
					if err != nil {
						t.Error("Cannot parse test case", err)
					}
					data.Param = p
				}
				op, err := Get(data.Name)
				if err != nil {
					t.Logf("skipped error: %v", err)
					return
				}

				opts := coraza.RuleOperatorOptions{
					Arguments: data.Param,
					Path:      []string{"./testdata/op"},
				}
				if err := op.Init(opts); err != nil {
					t.Error(err)
				}
				res := op.Evaluate(waf.NewTransaction(context.Background()), data.Input)
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
