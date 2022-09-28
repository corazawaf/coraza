// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	_ "fmt"
	"testing"

	"github.com/corazawaf/coraza/v3/rules"
)

func TestIpMatchFromDataset(t *testing.T) {
	addrok := []string{"127.0.0.1", "192.168.0.1", "192.168.0.253"}
	addrfail := []string{"127.0.0.2", "192.168.1.1"}

	ipm := &ipMatchFromDataset{}
	opts := rules.OperatorOptions{
		Arguments: "test_1",
		Datasets: map[string][]string{
			"test_1": {"127.0.0.1", "192.168.0.0/24"},
		},
	}

	if err := ipm.Init(opts); err != nil {
		t.Error("Cannot init ipmatchfromfile operator")
	}
	for _, ok := range addrok {
		if !ipm.Evaluate(nil, ok) {
			t.Errorf("Invalid result for single CIDR IpMatchFromDataset " + ok)
		}
	}

	for _, fail := range addrfail {
		if ipm.Evaluate(nil, fail) {
			t.Errorf("Invalid result for single CIDR IpMatchFromDataset" + fail)
		}
	}
}

func TestIpMatchFromEmptyDataset(t *testing.T) {
	ipm := &ipMatchFromDataset{}
	opts := rules.OperatorOptions{
		Arguments: "test_1",
		Datasets: map[string][]string{
			"test_1": {},
		},
	}
	if err := ipm.Init(opts); err == nil {
		t.Error("Empty dataset not checked")
	}
}
