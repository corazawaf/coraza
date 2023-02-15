// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"errors"
	"testing"
)

func TestRequestBodyLimit(t *testing.T) {
	testCases := map[string]struct {
		expectedErr   error
		limit         int
		inMemoryLimit int
	}{
		"empty limit": {
			limit:         0,
			inMemoryLimit: 2,
			expectedErr:   errors.New("request body limit should be bigger than 0"),
		},
		"empty memory limit": {
			limit:         2,
			inMemoryLimit: 0,
			expectedErr:   errors.New("request body memory limit should be bigger than 0"),
		},
		"memory limit bigger than limit": {
			limit:         5,
			inMemoryLimit: 9,
			expectedErr:   errors.New("request body limit should be at least the memory limit"),
		},
		"limit bigger than the hard limit": {
			limit:       1073741825,
			expectedErr: errors.New("request body limit should be at most 1GB"),
		},
		"right limits": {
			limit:         100,
			inMemoryLimit: 50,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := NewWAFConfig().(*wafConfig)
			cfg.requestBodyLimit = &tCase.limit
			cfg.requestBodyInMemoryLimit = &tCase.inMemoryLimit

			_, err := NewWAF(cfg)
			if tCase.expectedErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %s", err.Error())
				}
			} else {
				if err == nil {
					t.Fatal("expected error")
				}

				if want, have := tCase.expectedErr, err; want.Error() != have.Error() {
					t.Fatalf("unexpected error: want %q, have %q", want, have)
				}
			}
		})
	}
}

func TestResponseBodyLimit(t *testing.T) {
	testCases := map[string]struct {
		expectedErr error
		limit       int
	}{
		"empty limit": {
			limit:       0,
			expectedErr: errors.New("response body limit should be bigger than 0"),
		},
		"limit bigger than the hard limit": {
			limit:       1073741825,
			expectedErr: errors.New("response body limit should be at most 1GB"),
		},
		"right limit": {
			limit: 100,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := NewWAFConfig().(*wafConfig)
			cfg.responseBodyLimit = &tCase.limit

			_, err := NewWAF(cfg)
			if tCase.expectedErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %s", err.Error())
				}
			} else {
				if err == nil {
					t.Fatal("expected error")
				}

				if want, have := tCase.expectedErr, err; want.Error() != have.Error() {
					t.Fatalf("unexpected error: want %q, have %q", want, have)
				}
			}
		})
	}
}
