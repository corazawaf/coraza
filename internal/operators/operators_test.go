// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/tidwall/gjson"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/memoize"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
)

type Test struct {
	Input string
	Param string
	Name  string
	Ret   int
	Type  string
}

// TestMemoizeKeysAreContentBound builds two operators through one memoizer
// with the same argument but different content and checks that each matches
// only its own list. The memoizer's cache is process-global, so a key naming
// the content's source instead of the content hands the second WAF the first
// WAF's matcher (GHSA-wc2q-x24m-8c5f). Not a profile: it needs two WAFs.
func TestMemoizeKeysAreContentBound(t *testing.T) {
	const owner = 1 << 62
	m := memoize.NewMemoizer(owner)
	t.Cleanup(func() { memoize.Release(owner) })

	tests := []struct {
		name  string
		build func(word string) (plugintypes.Operator, error)
	}{
		{
			name: "pmFromDataset with the same dataset name",
			build: func(word string) (plugintypes.Operator, error) {
				return newPMFromDataset(plugintypes.OperatorOptions{
					Arguments: "list",
					Datasets:  map[string][]string{"list": {word}},
					Memoizer:  m,
				})
			},
		},
		{
			name: "pmFromFile with the same path on another root",
			build: func(word string) (plugintypes.Operator, error) {
				return newPMFromFile(plugintypes.OperatorOptions{
					Arguments: "list.txt",
					Path:      []string{"."},
					Root:      fstest.MapFS{"list.txt": {Data: []byte(word + "\n")}},
					Memoizer:  m,
				})
			},
		},
	}
	tx := corazawaf.NewWAF().NewTransaction()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			first, err := tc.build("evil-a")
			if err != nil {
				t.Fatal(err)
			}
			second, err := tc.build("evil-b")
			if err != nil {
				t.Fatal(err)
			}
			if !first.Evaluate(tx, "evil-a") || first.Evaluate(tx, "evil-b") {
				t.Error("first operator does not enforce its own list")
			}
			if !second.Evaluate(tx, "evil-b") {
				t.Error("second operator does not match its own entry")
			}
			if second.Evaluate(tx, "evil-a") {
				t.Error("second operator enforces the first operator's list")
			}
		})
	}
}

// https://github.com/SpiderLabs/secrules-language-tests/
func TestOperators(t *testing.T) {
	root := "./testdata"
	type corpusFile struct {
		name string
		data []byte
	}
	var files []corpusFile
	if _, err := os.Stat(root); os.IsNotExist(err) {
		t.Fatal("failed to find operator test files")
	}

	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".json") {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files = append(files, corpusFile{name: strings.TrimSuffix(filepath.Base(path), ".json"), data: data})
		}
		return nil
	}); err != nil {
		t.Fatalf("failed to walk test files: %s", err.Error())
	}

	notImplemented := []string{
		"containsWord",
		"verifyCC",
		"verifycpf",
		"verifyssn",
		"verifysvnr",
	}

	emptyArgumentRejected := []string{"beginsWith", "contains", "endsWith", "streq", "within"}

	captureMatrix := map[string]bool{
		"with capture":    true,
		"without capture": false,
	}

	waf := corazawaf.NewWAF()
	ran := 0
	for _, f := range files {
		cases := unmarshalTests(t, f.data)
		for i, data := range cases {
			if utils.InSlice(data.Name, notImplemented) {
				continue
			}
			name := fmt.Sprintf("%s/%d", f.name, i)

			// UNMARSHALL does not transform \u0000 to binary
			input := strings.ReplaceAll(data.Input, `\u0000`, "\u0000")
			param := strings.ReplaceAll(data.Param, `\u0000`, "\u0000")
			if strings.Contains(input, `\x`) {
				in, err := strconv.Unquote(`"` + input + `"`)
				if err != nil {
					t.Errorf("%s: cannot parse input: %s", name, err.Error())
					continue
				}
				input = in
			}
			if strings.Contains(param, `\x`) {
				p, err := strconv.Unquote(`"` + param + `"`)
				if err != nil {
					t.Errorf("%s: cannot parse param: %s", name, err.Error())
					continue
				}
				param = p
			}
			opts := plugintypes.OperatorOptions{
				Arguments: param,
				Path:      []string{"op"},
				Root:      os.DirFS("testdata"),
			}

			// ModSecurity matches every input against an empty argument; Coraza
			// rejects it when the rule is compiled (macro.NewMacro: "empty data").
			if param == "" && utils.InSlice(data.Name, emptyArgumentRejected) {
				t.Run(name+" empty argument rejected", func(t *testing.T) {
					if _, err := Get(data.Name, opts); err == nil {
						t.Errorf("@%s with an empty argument compiled; Coraza rejects it", data.Name)
					}
				})
				ran++
				continue
			}

			for capName, capVal := range captureMatrix {
				t.Run(name+" "+capName, func(t *testing.T) {
					op, err := Get(data.Name, opts)
					if err != nil {
						t.Error(err)
						return
					}
					tx := waf.NewTransaction()
					tx.Capture = capVal
					res := op.Evaluate(tx, input)
					// 1 = expected true
					// 0 = expected false
					if (res && data.Ret != 1) || (!res && data.Ret == 1) {
						expected := "match"
						if data.Ret == 0 {
							expected = "no match"
						}
						t.Errorf("Invalid operator result for @%s(%q, %q), %s expected", data.Name, param, input, expected)
					}
				})
				ran++
			}
		}
	}
	// The corpus was skipped entirely for three years without anyone noticing.
	if ran == 0 {
		t.Fatal("no operator corpus case ran")
	}
}

func unmarshalTests(t *testing.T, json []byte) []Test {
	t.Helper()
	var tests []Test
	v := gjson.ParseBytes(json).Value()
	for _, in := range v.([]any) {
		obj := in.(map[string]any)
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
