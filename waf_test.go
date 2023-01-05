// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import "testing"

func TestNewWAFLimits(t *testing.T) {
	_, err := NewWAF(&wafConfig{
		requestBody: &requestBodyConfig{
			limit:         5,
			inMemoryLimit: 9,
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}

	expectedErr := "request body limit should be at least the memory limit"
	if want, have := expectedErr, err.Error(); want != have {
		t.Errorf("unexpected error: want %q, have %q", want, have)
	}
}
