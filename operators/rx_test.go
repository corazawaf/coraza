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

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types/variables"
	"github.com/stretchr/testify/require"
)

func TestRx1(t *testing.T) {
	rx := &rx{}

	err := rx.Init("som(.*)ta")
	require.NoError(t, err)

	waf := coraza.NewWaf()
	tx := waf.NewTransaction()
	tx.Capture = true
	res := rx.Evaluate(tx, "somedata")
	require.True(t, res, "rx1 failed")

	vars := tx.GetCollection(variables.TX).Data()
	require.Equal(t, "somedata", vars["0"][0], "rx1 failed")
	require.Equal(t, "eda", vars["1"][0], "rx1 failed")
}
