// Copyright 2020 Juan Pablo Tosso
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

import(
	"testing"
	_"fmt"
	"github.com/jptosso/coraza-waf/test/utils"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

func TestBeginsWithUnicodeStringCorrect(t *testing.T) {
    data := utils.UnicodeString()
    bw := newBw(data[0:3])
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid BeginsWith transformation result")
    }
}

func TestBeginsWithUnicodeStringIncorrect(t *testing.T) {
    data := utils.UnicodeString()
    bw := newBw(data[3:5])
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if result {
    	t.Errorf("Invalid BeginsWith operator result")
    }
}

func TestBeginsWithHugeString(t *testing.T) {
    data := utils.GiantString(1000000)
    bw := newBw(data[0:115])
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid BeginsWith operator result")
    }
}

func TestBeginsWithEmptyString(t *testing.T) {
    data := ""
    bw := newBw(data)
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid BeginsWith operator result")
    }
}

func TestBeginsWithBinaryString(t *testing.T) {
    data := utils.BinaryString(1000)
    bw := newBw(data[0:10])
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid BeginsWith operator result")
    }    
}

func newBw(data string) engine.Operator{
	bw := &BeginsWith{}
	bw.Init(data)
	return bw
}

func newTx() engine.Transaction{
	tx := engine.Transaction{}
	return tx
}