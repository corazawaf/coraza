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

func TestOneAddress(t *testing.T) {
	addrok := "127.0.0.1"
	addrfail := "127.0.0.2"
	cidr := "127.0.0.1/32"
	ipm := &ipMatch{}
	if err := ipm.Init(cidr); err != nil {
		t.Error("Cannot init ipmatchtest operator")
	}
	if !ipm.Evaluate(nil, addrok) {
		t.Errorf("Invalid result for single CIDR IpMatch")
	}
	if ipm.Evaluate(nil, addrfail) {
		t.Errorf("Invalid result for single CIDR IpMatch")
	}
}

func TestMultipleAddress(t *testing.T) {
	addrok := []string{"127.0.0.1", "192.168.0.1", "192.168.0.253"}
	addrfail := []string{"127.0.0.2", "192.168.1.1"}
	cidr := "127.0.0.1, 192.168.0.0/24"
	ipm := &ipMatch{}
	if err := ipm.Init(cidr); err != nil {
		t.Error("Cannot init ipmatchtest operator")
	}
	for _, ok := range addrok {
		if !ipm.Evaluate(nil, ok) {
			t.Errorf("Invalid result for single CIDR IpMatch " + ok)
		}
	}

	for _, fail := range addrfail {
		if ipm.Evaluate(nil, fail) {
			t.Errorf("Invalid result for single CIDR IpMatch" + fail)
		}
	}
}

func TestFromFile(t *testing.T) {
	addrok := []string{"127.0.0.1", "192.168.0.1", "192.168.0.253"}
	addrfail := []string{"127.0.0.2", "192.168.1.1"}

	ipm := &ipMatchFromFile{}
	if err := ipm.Init("../testdata/operators/op/netranges.dat"); err != nil {
		t.Error("Cannot init ipmatchfromfile operator")
	}
	for _, ok := range addrok {
		if !ipm.Evaluate(nil, ok) {
			t.Errorf("Invalid result for single CIDR IpMatchFromFile " + ok)
		}
	}

	for _, fail := range addrfail {
		if ipm.Evaluate(nil, fail) {
			t.Errorf("Invalid result for single CIDR IpMatchFromFile" + fail)
		}
	}
}
