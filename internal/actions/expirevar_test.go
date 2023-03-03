// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import "testing"

func TestExpirevarInit(t *testing.T) {
	for _, test := range []struct {
		data          string
		expectedError bool
	}{
		{"", true},
		{"session", true},
		{"session.suspicious", true},
		{"session.suspicious=abc", true},
		{"session.suspicious=-3600", true},
		{"session.suspicious=3600", false},
	} {
		a := expirevar()
		err := a.Init(nil, test.data)
		if test.expectedError {
			if err == nil {
				t.Errorf("expected error: %s", err.Error())
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}
		}
	}
}
