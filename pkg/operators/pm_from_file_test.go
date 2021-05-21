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
	_ "fmt"
	"testing"
)

func TestPmFromFile1(t *testing.T) {
	match := []string{
		"this is a test1 string with many tests.",
		"asdfjava.io.BufferedInputStream=test asdfasdf",
	}
	nomatch := []string{
		"this is the same test string without a match.",
	}
	pmf := &PmFromFile{}
	pmf.Init("")
	pmf.Data = []string{"test1", "match1", "java.io.BufferedInputStream=test"}
	for _, m := range match {
		if !pmf.Evaluate(nil, m) {
			t.Errorf("Invalid result for pmf, must match")
		}
	}
	for _, nm := range nomatch {
		if pmf.Evaluate(nil, nm) {
			t.Errorf("Invalid result for musn't match")
		}
	}
}
