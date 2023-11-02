// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package persistence

import "testing"

func TestNoopEngine(t *testing.T) {
	ne, err := Get("noop")
	if err != nil {
		t.Error("Failed to get noop engine")
	}
	ne.Open("", 100)                       //nolint:errcheck
	ne.Close()                             //nolint:errcheck
	ne.Get("test", "test", "test")         //nolint:errcheck
	ne.Set("test", "test", "test", "test") //nolint:errcheck
	ne.Remove("test", "test", "test")      //nolint:errcheck
}
