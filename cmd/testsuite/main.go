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

// This tool is designed to imitate the OWASP CRS WAF testing framework ftw and can be used to automate WAF testing for DevSecOps.
// Coraza WAF Testsuite does not require a web server as it is used as a standalone library, providing better feedback and faster.
// This tool only works with Coraza WAF.
package main

import (
	"flag"
	"fmt"
	test "github.com/jptosso/coraza-waf/test/utils"
	"os"
	"path/filepath"
	"strings"
)

var debug = false
var failonly = false

func main() {
	path := flag.String("path", "./", "Path to find yaml files")
	rules := flag.String("rules", "/tmp/rules.conf", "Path to rule files for testing.")
	//fo := flag.Bool("fo", false, "Filter by fails only.")
	//proxy := flag.String("p", "", "Tests will be proxied to this url, example: https://10.10.10.10:443")
	//duration := flag.Int("d", 500, "Max tests duration in seconds.")
	//iterations := flag.Int("i", 1, "Max test iterations.")
	//concurrency := flag.Int("c", 1, "How many concurrent routines.")
	//dodebug := flag.Bool("d", false, "Show debug information.")
	flag.Parse()

	ts := &test.TestSuite{}
	ts.Init(*rules)
	files, err := getYamlFromDir(*path)
	if err != nil {
		panic("Cannot load path " + *path)
	}
	i := 0
	for _, f := range files {
		ts.AddProfile(f)
		i++
	}
	fmt.Printf("Loaded %d profiles.\n", i)
	ts.Start(func(name string, pass bool) {
		result := "\033[31mFailed"
		if pass {
			result = "\033[32mPassed"
		}
		fmt.Printf("%s: %s\033[0m\n", name, result)
	})
}

func getYamlFromDir(directory string) ([]string, error) {
	files := []string{}
	err := filepath.Walk(directory,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if strings.HasSuffix(path, ".yaml") {
				files = append(files, path)
			}
			return nil
		})
	if err != nil {
		return files, err
	}
	return files, nil
}
