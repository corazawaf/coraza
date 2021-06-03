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
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/parser"
	"os"
	"path"
	"path/filepath"
	"strings"
	//log "github.com/sirupsen/logrus"
)

var debug = false
var failonly = false

func main() {
	rpath := flag.String("path", "./", "Path to find yaml files")
	rules := flag.String("rules", "/tmp/rules.conf", "Path to rule files for testing.")
	//fo := flag.Bool("fo", false, "Filter by fails only.")
	//proxy := flag.String("p", "", "Tests will be proxied to this url, example: https://10.10.10.10:443")
	//duration := flag.Int("d", 500, "Max tests duration in seconds.")
	//iterations := flag.Int("i", 1, "Max test iterations.")
	//concurrency := flag.Int("c", 1, "How many concurrent routines.")
	//dodebug := flag.Bool("d", false, "Show debug information.")
	flag.Parse()
	//log.SetLevel(log.DebugLevel)

	files, err := getYamlFromDir(*rpath)
	if err != nil {
		panic("Cannot load path " + *rpath)
	}
	waf := engine.NewWaf()
	waf.Datapath = path.Dir(*rules)
	parser := &parser.Parser{}
	parser.Init(waf)
	parser.FromFile(*rules)		
	err = evaluateFiles(waf, files)
	if err != nil {
		fmt.Println(err)
	}
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

func evaluateFiles(waf *engine.Waf, files []string) error {
	for _, f := range files {
		profile, err := test.ParseProfile(f)
		if err != nil {
			return err
		}
		for _, t := range profile.Tests {
			fmt.Println("Running test suite " + t.Title)
			for i, s := range t.Stages {
				err := s.Start(waf, profile.Rules)
				if err != nil {
					fmt.Printf("\033[0;31mStage %d: %s\033[0m\n", i+1, err)
				}
			}
		}		
	}
	return nil
}
