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
)

func TestPm(t *testing.T) {
	pm := &Pm{}
	pm.Init("abc def ghi")
	if !pm.Evaluate(nil, "test ab abc 123") {
		t.Errorf("Invalid result for @pm operator")
	}
	if pm.Evaluate(nil, "abedfegih 456") {
		t.Errorf("Invalid result for @pm operator")
	}
	if !pm.Evaluate(nil, "abcdefghijk456") {
		t.Errorf("Invalid result for @pm operator")
	}
}
