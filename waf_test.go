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
	"testing"

	"github.com/stretchr/testify/require"
)

var waf *Waf

func TestWAFInitialize(_ *testing.T) {
	waf = NewWaf()
}

func TestNewTransaction(t *testing.T) {
	waf := NewWaf()
	waf.RequestBodyAccess = true
	waf.ResponseBodyAccess = true
	waf.RequestBodyLimit = 1044
	tx := waf.NewTransaction()
	require.True(t, tx.RequestBodyAccess, "Request body access not enabled")
	require.True(t, tx.ResponseBodyAccess, "Response body access not enabled")
	require.Equal(t, int64(1044), tx.RequestBodyLimit, "Request body limit not set")
}
