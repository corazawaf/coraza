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
	"testing"
)

func TestLe(t *testing.T) {
	le := &Le{}
	le.Init("2500")
	if !le.Evaluate(nil, "2400") {
		t.Errorf("Invalid result for @le operator")
	}
	if !le.Evaluate(nil, "2500") {
		t.Errorf("Invalid result for @le operator")
	}
	if le.Evaluate(nil, "2800") {
		t.Errorf("Invalid result for @le operator")
	}
}
