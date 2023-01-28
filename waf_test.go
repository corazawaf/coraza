// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import "testing"

func TestNewWAFLimits(t *testing.T) {
	testCases := map[string]struct {
		expectedErr   string
		limit         int
		inMemoryLimit int
	}{
		"empty limit": {
			expectedErr:   "request body limit should be bigger than 0",
			limit:         0,
			inMemoryLimit: 2,
		},
		"empty memory limit": {
			expectedErr:   "request body memory limit should be bigger than 0",
			limit:         2,
			inMemoryLimit: 0,
		},
		"memory limit bigger than limit": {
			limit:         5,
			inMemoryLimit: 9,
			expectedErr:   "request body limit should be at least the memory limit",
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			_, err := NewWAF(&wafConfig{
				requestBodyLimit:         tCase.limit,
				requestBodyInMemoryLimit: tCase.inMemoryLimit,
			})

			if tCase.expectedErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}

				if want, have := tCase.expectedErr, err.Error(); want != have {
					t.Fatalf("unexpected error: want %q, have %q", want, have)
				}
			}
		})
	}
}
