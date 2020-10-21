// Copyright 2020 Juan Pablo Tosso
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

package main

import (
	"flag"
	"fmt"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/parser"
	"os"
)

func main() {
	file := flag.String("f", "", "path of WAF config file to test")
	flag.Parse()

	if *file == "" {
		fmt.Println("-f is mandatory.")
		os.Exit(1)
	}

	waf := &engine.Waf{}
	waf.Init()

	p := &parser.Parser{}
	p.Init(waf)

	if p.FromFile(*file) != nil {
		fmt.Println("Exited with errors")
		os.Exit(11)
	}
	fmt.Println("Exited without errors.")
}
