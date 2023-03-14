// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import "testing"

func TestDefaultWriters(t *testing.T) {
	ws := []string{"serial", "concurrent"}
	for _, writer := range ws {
		if w, err := GetWriter(writer); err != nil {
			t.Error(err)
		} else if w == nil {
			t.Errorf("invalid %s writer", writer)
		}
	}
}
