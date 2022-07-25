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
	"github.com/stretchr/testify/require"
)

func TestPmfm(t *testing.T) {
	data := "abc\r\ndef\r\nghi\njkl\ryhz"
	p := &pmFromFile{}

	err := p.Init(data)
	require.NoError(t, err)

	waf := coraza.NewWaf()
	tx := waf.NewTransaction()
	require.True(t, p.Evaluate(tx, "def"), "failed to match pmFromFile")
}
