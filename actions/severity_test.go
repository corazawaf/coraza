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

package actions

import (
	"testing"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types"
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
			rule := coraza.NewRule()
			sev := severity()
			if err := sev.Init(rule, tt.name); err != nil {
				t.Error(err)
			}
			if got := rule.Severity; got != tt.want {
				t.Errorf("Severity = %v, want %v", got, tt.want)
			}
		})
	}
}
