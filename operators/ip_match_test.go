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

import (
	_ "fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOneAddress(t *testing.T) {
	addrok := "127.0.0.1"
	addrfail := "127.0.0.2"
	cidr := "127.0.0.1/32"
	ipm := &ipMatch{}

	err := ipm.Init(cidr)
	require.NoError(t, err, "cannot init ipmatchtest operator")
	require.True(t, ipm.Evaluate(nil, addrok), "invalid result for single CIDR IpMatch")
	require.False(t, ipm.Evaluate(nil, addrfail), "invalid result for single CIDR IpMatch")
}

func TestMultipleAddress(t *testing.T) {
	addrok := []string{"127.0.0.1", "192.168.0.1", "192.168.0.253"}
	addrfail := []string{"127.0.0.2", "192.168.1.1"}
	cidr := "127.0.0.1, 192.168.0.0/24"
	ipm := &ipMatch{}

	err := ipm.Init(cidr)
	require.NoError(t, err, "cannot init ipmatchtest operator")

	for _, ok := range addrok {
		t.Run(ok, func(t *testing.T) {
			require.True(t, ipm.Evaluate(nil, ok), "invalid result for single CIDR IpMatch")
		})
	}

	for _, fail := range addrfail {
		t.Run(fail, func(t *testing.T) {
			require.False(t, ipm.Evaluate(nil, fail), "invalid result for single CIDR IpMatch")
		})
	}
}

func TestFromFile(t *testing.T) {
	addrok := []string{"127.0.0.1", "192.168.0.1", "192.168.0.253"}
	addrfail := []string{"127.0.0.2", "192.168.1.1"}

	ipm := &ipMatchFromFile{}
	data, err := os.ReadFile("../testdata/operators/op/netranges.dat")
	require.NoError(t, err, "cannot read test data")

	err = ipm.Init(string(data))
	require.NoError(t, err, "cannot init ipmatchfromfile operator")

	for _, ok := range addrok {
		t.Run(ok, func(t *testing.T) {
			require.True(t, ipm.Evaluate(nil, ok), "invalid result for single CIDR IpMatchFromFile")
		})
	}

	for _, fail := range addrfail {
		t.Run(fail, func(t *testing.T) {
			require.False(t, ipm.Evaluate(nil, fail), "invalid result for single CIDR IpMatchFromFile")
		})
	}
}
