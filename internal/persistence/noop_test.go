// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package persistence

import "testing"

func TestNoopEngine(t *testing.T) {
	ne, err := Get("noop")
	if err != nil {
		t.Error("Failed to get noop engine")
	}
	_ = ne.Open("", 100)
	_ = ne.Close()
	_, _ = ne.Get("test", "test", "test")
	_ = ne.Set("test", "test", "test", "test")
	_ = ne.Remove("test", "test", "test")
}
