// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v4/internal/corazawaf"
)

func TestLogDataInit(t *testing.T) {
	for name, test := range map[string]struct {
		data        string
		expectError bool
	}{
		"empty":   {"", true},
		"valid":   {"%{tx.count}", false},
		"invalid": {"%{tx.count", true},
	} {
		t.Run(name, func(t *testing.T) {
			action := logdata()
			r := &corazawaf.Rule{}
			err := action.Init(r, test.data)
			if test.expectError && err == nil {
				t.Errorf("expected error")
			} else if !test.expectError && err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}
		})
	}
}
