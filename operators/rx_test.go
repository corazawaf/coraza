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
	"strconv"
	"testing"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types/variables"
)

func TestRx1(t *testing.T) {
	rx := &rx{}
	if err := rx.Init("."); err != nil {
		t.Error(err)
	}
	waf := coraza.NewWaf()
	tx := waf.NewTransaction()
	tx.Capture = true
	res := rx.Evaluate(tx, "somedata")
	if !res {
		t.Error("rx1 failed")
	}
	vars := tx.GetCollection(variables.TX).Data()
	if vars["0"][0] != "somedata" {
		t.Error("rx1 failed")
	}
	for i, c := range "somedata" {
		istr := strconv.Itoa(i + 1)
		if vars[istr][0] != string(c) {
			t.Errorf("rx1 failed, expected %s, got %s", string(c), vars[istr][0])
		}
	}
}
