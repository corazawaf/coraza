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

import "testing"

func TestNidCl(t *testing.T) {
	ok := []string{"11.111.111-1", "16100407-3", "8.492.655-8", "84926558", "111111111", "5348281-3", "10727393-k", "10727393-K"}
	nok := []string{"11.111.111-k", "16100407-2", "8.492.655-7", "84926557", "111111112", "5348281-4"}
	for _, o := range ok {
		if !nidCl(o) {
			t.Errorf("Invalid NID CL for %s", o)
		}
	}

	for _, o := range nok {
		if nidCl(o) {
			t.Errorf("Valid NID CL for %s", o)
		}
	}
	if nidCl("") {
		t.Errorf("Valid NID CL for empty string")
	}
}
