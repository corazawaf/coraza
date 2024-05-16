// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.rule.case_sensitive_args_keys

package corazawaf

import (
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestCaseSensitiveArgsVariableKeys(t *testing.T) {
	rule := NewRule()
	if err := rule.AddVariable(variables.ArgsGet, "Som3ThinG", false); err != nil {
		t.Error(err)
	}
	if rule.variables[0].KeyStr != "Som3ThinG" {
		t.Error("variable key is not case insensitive")
	}
}
