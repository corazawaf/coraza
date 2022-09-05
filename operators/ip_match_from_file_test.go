// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"testing"
)

func TestFromFile(t *testing.T) {
	addrok := []string{"127.0.0.1", "192.168.0.1", "192.168.0.253"}
	addrfail := []string{"127.0.0.2", "192.168.1.1"}

	ipm := &ipMatchFromFile{}
	opts := corazawaf.RuleOperatorOptions{
		Arguments: string("./testdata/op/netranges.dat"),
		Path:      []string{"."},
	}
	if err := ipm.Init(opts); err != nil {
		t.Error("Cannot init ipmatchfromfile operator")
	}
	for _, ok := range addrok {
		t.Run(ok, func(t *testing.T) {
			if !ipm.Evaluate(nil, ok) {
				t.Errorf("Invalid result for single CIDR IpMatchFromFile")
			}
		})
	}

	for _, fail := range addrfail {
		t.Run(fail, func(t *testing.T) {
			if ipm.Evaluate(nil, fail) {
				t.Errorf("Invalid result for single CIDR IpMatchFromFile")
			}
		})
	}
}
