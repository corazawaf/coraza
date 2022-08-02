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

package testing

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestEngine(t *testing.T) {
	files, err := filepath.Glob("../testdata/engine/*.json")
	if err != nil {
		t.Error(err)
	}
	if len(files) == 0 {
		t.Error("failed to find test files")
	}
	for _, f := range files {
		profile, err := NewProfile(f)
		if err != nil {
			t.Errorf("failed to parse profile %s: %s", f, err)
		}
		if profile.TinyGoDisable && IsTinyGo {
			continue
		}
		tt, err := profile.TestList(nil)
		if err != nil {
			t.Error(err)
		}
		for _, test := range tt {
			testname := profile.Tests[0].Title

			t.Run(testname, func(t *testing.T) {
				if err := test.RunPhases(); err != nil {
					t.Errorf("%s, ERROR: %s", test.Name, err)
				}

				for _, e := range test.OutputErrors() {
					debug := ""
					for _, mr := range test.transaction.MatchedRules {
						debug += fmt.Sprintf(" %d", mr.Rule.ID)
					}
					if testing.Verbose() {
						t.Errorf("\x1b[41m ERROR \x1b[0m: %s:%s: %s, got:%s\n%s\nREQUEST:\n%s", profile.Meta.Name, test.Name, e, debug, test.transaction.Debug(), test.Request())
					} else {
						t.Errorf("%s: ERROR: %s", test.Name, e)
					}
				}

				for _, e := range test.OutputInterruptionErrors() {
					if testing.Verbose() {
						t.Errorf("\x1b[41m ERROR \x1b[0m: %s:%s: %s\n %s\nREQUEST:\n%s", profile.Meta.Name, test.Name, e, test.transaction.Debug(), test.Request())
					} else {
						t.Errorf("%s: ERROR: %s", test.Name, e)
					}
				}
			})
		}
	}
}
