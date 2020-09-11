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
)

func TestInspectFile(t *testing.T) {
    ipf := &InspectFile{}
    ipf.Init("/bin/echo")
    if !ipf.Evaluate(nil, "test") {
    	t.Errorf("/bin/echo returned exit code other than 0")
    }
    ipf.Init("/bin/nonexistant")
    if ipf.Evaluate(nil, "test") {
        t.Errorf("/bin/nonexistant returned an invalid exit code")
    }    
}