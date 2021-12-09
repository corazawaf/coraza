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

package operators

import (
	"testing"

	engine "github.com/jptosso/coraza-waf/v2"
)

func TestCRS920272(t *testing.T) {
	ranges := "32-36,38-126"
	goodStrings := [][]byte{
		{104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111},
		{38, 104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, 126},
		{32, 104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, 125},
	}

	badStrings := [][]byte{
		{35, 38, 104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 127, 128},
		{104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, 0},
		{104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, 0},
	}

	op := &validateByteRange{}
	if err := op.Init(ranges); err != nil {
		t.Error("Cannot init validatebuterange operator")
	}
	tx := getTransaction()

	for _, gs := range goodStrings {
		str := string(gs)
		if !op.Evaluate(tx, str) {
			t.Errorf("Invalid byte between ranges (positive): %s", str)
		}
	}

	for _, bs := range badStrings {
		str := string(bs)
		if !op.Evaluate(tx, str) {
			t.Errorf("Invalid byte between ranges (negative): %s", str)
		}
	}
}

func TestCRS920270(t *testing.T) {
	ranges := "1-255"
	goodStrings := [][]byte{
		{104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111},
		{38, 104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, 126},
		{32, 104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, 125},
		{1, 104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, 255},
	}

	op := &validateByteRange{}
	if err := op.Init(ranges); err != nil {
		t.Error("Cannot init validatebuterange operator")
	}
	tx := getTransaction()

	for _, gs := range goodStrings {
		str := string(gs)
		if op.Evaluate(tx, str) {
			t.Errorf("Invalid null byte: %s", str)
		}
	}
}

func TestValidateByteRangeCase4(t *testing.T) {
	ranges := "0-255"
	op := &validateByteRange{}
	if err := op.Init(ranges); err != nil {
		t.Error("Cannot init validatebuterange operator")
	}
	tx := getTransaction()
	if op.Evaluate(tx, "\u00d0\u0090") {
		t.Error("Invalid byte between ranges (negative)", []byte("\u00d0\u0090"))
	}
}

func getTransaction() *engine.Transaction {
	waf := engine.NewWaf()
	return waf.NewTransaction()
}
