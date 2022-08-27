// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	_ "fmt"
	"os"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestOneAddress(t *testing.T) {
	addrok := "127.0.0.1"
	addrfail := "127.0.0.2"
	cidr := "127.0.0.1/32"
	ipm := &ipMatch{}
	opts := coraza.RuleOperatorOptions{
		Arguments: cidr,
	}
	if err := ipm.Init(opts); err != nil {
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
	opts := coraza.RuleOperatorOptions{
		Arguments: cidr,
	}
	if err := ipm.Init(opts); err != nil {
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
	data, err := os.ReadFile("./testdata/op/netranges.dat")
	if err != nil {
		t.Error("Cannot read test data", err)
	}
	opts := coraza.RuleOperatorOptions{
		Arguments: string(data),
	}
	if err := ipm.Init(opts); err != nil {
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
