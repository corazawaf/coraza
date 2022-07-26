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

package coraza

import (
	"regexp"
	"testing"

	"github.com/corazawaf/coraza/v2/types/variables"
	"github.com/stretchr/testify/require"
)

func TestLocalCollection(t *testing.T) {
}

func TestLocalCollectionMatchData(t *testing.T) {
	lc := NewCollection(variables.Args)
	lc.Set("test2", []string{"test3"})
	lc.Set("other4", []string{"test"})
	require.Len(t, lc.FindRegex(regexp.MustCompile("test.*")), 1, "failed to find regex")
	require.Len(t, lc.FindString("other4"), 1, "failed to find string")
}

func TestAddUnique(t *testing.T) {
	col := NewCollection(variables.Args)
	col.AddUnique("test", "test2")
	col.AddUnique("test", "test2")
	require.Len(t, col.data["test"], 1, "failed to add unique")
	require.Equal(t, "test2", col.data["test"][0].Value, "failed to add unique")
}
