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

package testing

import (
	"fmt"
	"path/filepath"
	"testing"

	engine "github.com/jptosso/coraza-waf"
	"github.com/jptosso/coraza-waf/seclang"
)

func TestEngine(t *testing.T) {
	files, err := filepath.Glob("../testdata/engine/*.yaml")
	if err != nil {
		t.Error(err)
	}
	if len(files) == 0 {
		t.Error("failed to find test files")
	}
	waf := engine.NewWaf()
	for _, f := range files {
		profile, err := NewProfile(f)
		if err != nil {
			t.Error(err)
		}
		for _, tt := range profile.Tests {
			for _, s := range tt.Stages {
				var err error
				if profile.Rules == "" {
					err = s.Start(waf)
				} else {
					w := engine.NewWaf()
					p, _ := seclang.NewParser(w)
					if err := p.FromString(profile.Rules); err != nil {
						panic(err)
					}
					err = s.Start(w)
				}

				if err != nil {
					t.Error(fmt.Sprintf("%s: %s\n", f, err.Error()))
				}
			}
		}
	}
}
