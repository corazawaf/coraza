// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
)

func TestSeverity(t *testing.T) {
	tests := []struct {
		name string
		want types.RuleSeverity
	}{
		// string input
		{"EMERGENCY", 0},
		{"ALERT", 1},
		{"CRITICAL", 2},
		{"ERROR", 3},
		{"WARNING", 4},
		{"NOTICE", 5},
		{"INFO", 6},
		{"DEBUG", 7},
		// numeric input
		{"0", 0},
		{"1", 1},
		{"2", 2},
		{"3", 3},
		{"4", 4},
		{"5", 5},
		{"6", 6},
		{"7", 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := corazawaf.NewRule()
			sev := severity()
			if err := sev.Init(rule, tt.name); err != nil {
				t.Error(err)
			}
			if got := rule.Severity; got != tt.want {
				t.Errorf("Severity = %s, want %s", got.String(), tt.want.String())
			}
		})
	}
}
