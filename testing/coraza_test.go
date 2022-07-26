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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngine(t *testing.T) {
	files, err := filepath.Glob("../testdata/engine/*.yaml")
	require.NoError(t, err)
	require.True(t, len(files) > 0)

	for _, f := range files {
		profile, err := NewProfile(f)
		assert.NoError(t, err)

		tt, err := profile.TestList(nil)
		assert.NoError(t, err)

		t.Run(profile.Meta.Name, func(t *testing.T) {
			for _, test := range tt {
				t.Run(test.Name, func(t *testing.T) {
					err = test.RunPhases()
					assert.NoError(t, err)

					for _, e := range test.OutputErrors() {
						debug := ""
						for _, mr := range test.transaction.MatchedRules {
							debug += fmt.Sprintf(" %d", mr.Rule.ID)
						}
						t.Errorf("%s\nGot: %s\n%s\nREQUEST:\n%s", e, debug, test.String(), test.Request())
					}
				})
			}
		})
	}
}
