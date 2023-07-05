// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package memoize

import "testing"

func TestCache(t *testing.T) {
	tc := newCache()

	_, found := tc.get("key1")
	if want, have := false, found; want != have {
		t.Fatalf("unexpected value, want %t, have %t", want, have)
	}

	tc.set("key1", 1)

	item, found := tc.get("key1")
	if want, have := true, found; want != have {
		t.Fatalf("unexpected value, want %t, have %t", want, have)
	}

	if want, have := 1, item.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	tc.Close()

	tc.set("key1", 1)

	_, found = tc.get("key1")
	if want, have := false, found; want != have {
		t.Fatalf("unexpected value, want %t, have %t", want, have)
	}
}
