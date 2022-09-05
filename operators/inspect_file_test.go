// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package operators

import (
	_ "fmt"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestInspectFile(t *testing.T) {
	ipf := &inspectFile{}
	opts := corazawaf.RuleOperatorOptions{
		Arguments: "",
	}
	opts.Arguments = "/bin/echo"
	if err := ipf.Init(opts); err != nil {
		t.Error("cannot init inspectfile operator")
	}
	if !ipf.Evaluate(nil, "test") {
		t.Errorf("/bin/echo returned exit code other than 0")
	}
	opts.Arguments = "/bin/nonexistant"
	if err := ipf.Init(opts); err != nil {
		t.Error("cannot init inspectfile operator")
	}
	if ipf.Evaluate(nil, "test") {
		t.Errorf("/bin/nonexistant returned an invalid exit code")
	}
}
