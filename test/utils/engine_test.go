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

package utils

import (
	"testing"
)

func TestEngine(t *testing.T) {
	files := []string{
		"../data/engine/persistence.yaml",
		"../data/engine/phases.yaml",
		"../data/engine/actions.yaml",
		"../data/engine/directives.yaml",
		"../data/engine/ctl.yaml",
		"../data/engine/variables.yaml",
		"../data/engine/transformations.yaml",
		"../data/engine/match.yaml",
		"../data/engine/chains.yaml",
	}

	ts := &TestSuite{}
	ts.Init("/dev/null")

	for _, f := range files {
		err := ts.AddProfile(f)
		if err != nil {
			t.Error(err)
		}
	}
	ts.Start(func(a string, b bool) {
		if !b {
			t.Error("Failed to run engine test: " + a)
		}
	})
}
