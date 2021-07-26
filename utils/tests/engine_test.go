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
	"fmt"
	"testing"

	"github.com/jptosso/coraza-waf/v1/engine"
)

func TestEngine(t *testing.T) {
	files := []string{
		"../../test/data/engine/body_processors.yaml",
		"../../test/data/engine/persistence.yaml",
		"../../test/data/engine/phases.yaml",
		"../../test/data/engine/actions.yaml",
		"../../test/data/engine/directives.yaml",
		"../../test/data/engine/ctl.yaml",
		"../../test/data/engine/variables.yaml",
		"../../test/data/engine/transformations.yaml",
		"../../test/data/engine/match.yaml",
		"../../test/data/engine/chains.yaml",
	}
	waf := engine.NewWaf()
	for _, f := range files {
		profile, err := ParseProfile(f)
		if err != nil {
			t.Error(err)
		}
		for _, tt := range profile.Tests {
			for _, s := range tt.Stages {
				err := s.Start(waf, profile.Rules)
				if err != nil {
					t.Error(fmt.Sprintf("%s: %s\n", f, err.Error()))
				}
			}
		}
	}
}
