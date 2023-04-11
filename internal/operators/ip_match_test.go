// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	_ "fmt"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestOneAddress(t *testing.T) {
	addrok := "127.0.0.1"
	addrfail := "127.0.0.2"
	cidr := "127.0.0.1/32"
	opts := plugintypes.OperatorOptions{
		Arguments: cidr,
	}
	ipm, err := newIPMatch(opts)
	if err != nil {
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
	opts := plugintypes.OperatorOptions{
		Arguments: cidr,
	}
	ipm, err := newIPMatch(opts)
	if err != nil {
		t.Error("Cannot init ipmatchtest operator")
	}
	for _, ok := range addrok {
		if !ipm.Evaluate(nil, ok) {
			t.Errorf("Invalid result for single CIDR IpMatch: %s", ok)
		}
	}

	for _, fail := range addrfail {
		if ipm.Evaluate(nil, fail) {
			t.Errorf("Invalid result for single CIDR IpMatch: %s", fail)
		}
	}
}
