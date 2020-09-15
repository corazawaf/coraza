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

import (
	_ "fmt"
	_ "github.com/jptosso/coraza-waf/pkg/engine"
	_ "github.com/jptosso/coraza-waf/test/utils"
	_ "testing"
)

/*
func TestDetectSqliUnicodeStringCorrect(t *testing.T) {
    bw := newSqli("")
    tx := newTx()
    for _, data := range utils.SQL_INJECTIONS{
        result := bw.Evaluate(&tx, data)
        if !result {
            t.Errorf("Invalid sql injection test: %q", data)
        }
    }
}

func TestDetectSqliUnicodeStringIncorrect(t *testing.T) {
    data := utils.UnicodeString()
    bw := newSqli(data[3:5])
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if result {
    	t.Errorf("Invalid DetectSqli operator result")
    }
}

func TestDetectSqliHugeString(t *testing.T) {
    data := utils.GiantString(1000000)
    bw := newSqli(data[0:115])
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid DetectSqli operator result")
    }
}

func TestDetectSqliEmptyString(t *testing.T) {
    data := ""
    bw := newSqli(data)
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid DetectSqli operator result")
    }
}

func TestDetectSqliBinaryString(t *testing.T) {
    data := utils.BinaryString(1000)
    bw := newSqli(data[0:10])
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid DetectSqli operator result")
    }
}

func newSqli(data string) engine.Operator{
	bw := &DetectSQLi{}
	bw.Init(data)
	return bw
}*/
