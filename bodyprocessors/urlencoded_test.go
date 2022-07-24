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

package bodyprocessors

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestURLEncode(t *testing.T) {
	bp := &urlencodedBodyProcessor{}
	argCol := collection.NewCollectionMap(variables.ArgsPost)
	bodyCol := collection.NewCollectionSimple(variables.RequestBody)
	bodyLenCol := collection.NewCollectionSimple(variables.RequestBodyLength)
	cols := [types.VariablesCount]collection.Collection{
		variables.ArgsPost:          argCol,
		variables.RequestBody:       bodyCol,
		variables.RequestBodyLength: bodyLenCol,
	}
	m := map[string]string{
		"a": "1",
		"b": "2",
		"c": "3",
	}
	// m to urlencoded string
	body := ""
	for k, v := range m {
		body += k + "=" + v + "&"
	}
	body = strings.TrimSuffix(body, "&")
	if err := bp.ProcessRequest(strings.NewReader(body), cols, Options{}); err != nil {
		t.Error(err)
	}
	if bodyCol.String() != body {
		t.Errorf("Expected %s, got %s", body, bodyCol.String())
	}
	if bodyLenCol.Int() != len(body) {
		t.Errorf("Expected %d, got %s", len(body), bodyLenCol.String())
	}
	for k, v := range m {
		if argCol.Get(k)[0] != v {
			t.Errorf("Expected %s, got %s", v, argCol.Get(k)[0])
		}
	}
}
