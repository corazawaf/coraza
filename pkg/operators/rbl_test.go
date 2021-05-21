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

func TestRbl(t *testing.T) {
	rbl := &Rbl{}
	rbl.Init("xbl.spamhaus.org")
	// Twitter ip address
	if rbl.Evaluate(nil, "199.16.156.5") {
		t.Errorf("Invalid result for @rbl operator")
	}
	// Facebook ip address
	if rbl.Evaluate(nil, "176.13.13.13") {
		t.Errorf("Invalid result for @rbl operator")
	}
	/*
	   // We dont have any permanently banned ip address :(
	   if !rbl.Evaluate(nil, "71.6.158.166") {
	       t.Errorf("Invalid result for @rbl operator, should be blacklisted")
	   }
	*/
}
