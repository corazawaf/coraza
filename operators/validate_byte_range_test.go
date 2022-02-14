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

	engine "github.com/corazawaf/coraza/v2"
)

func TestValidateByteRangeCase4(t *testing.T) {
	ranges := "0-255"
	op := &validateByteRange{}
	if err := op.Init(ranges); err != nil {
		t.Error("Cannot init byte range operator")
	}
	tx := getTransaction()
	if op.Evaluate(tx, "\u00d0\u0090") {
		t.Error("Invalid byte between ranges (negative)", []byte("\u00d0\u0090"))
	}
}

func TestValidateByteRangeCase5(t *testing.T) {
	ranges := "9,10,13,32-126,128-255"
	op := &validateByteRange{}
	if err := op.Init(ranges); err != nil {
		t.Error("Cannot init byte range operator")
	}
	if len(op.data) != 5 || op.data[0][0] != 9 || op.data[1][0] != 10 || op.data[2][0] != 13 || op.data[3][0] != 32 || op.data[3][1] != 126 || op.data[4][0] != 128 || op.data[4][1] != 255 {
		t.Error("Invalid range length", len(op.data))
	}
	if op.Evaluate(nil, "/\ufffdindex.html?test=test1") {
		t.Error("Invalid byte between ranges (negative)", []byte("/\ufffdindex.html?test=test1"))
	}
}

func getTransaction() *engine.Transaction {
	waf := engine.NewWaf()
	return waf.NewTransaction()
}
