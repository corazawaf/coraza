// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo && memoize_builders

// https://github.com/kofalt/go-memoize/blob/master/memoize.go

package memoize

import (
	"errors"
	"sync"
	"testing"
)

func TestDo(t *testing.T) {
	expensiveCalls := 0

	// Function tracks how many times its been called
	expensive := func() (interface{}, error) {
		expensiveCalls++
		return expensiveCalls, nil
	}

	// First call SHOULD NOT be cached
	result, err := Do("key1", expensive)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if want, have := 1, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	// Second call on same key SHOULD be cached
	result, err = Do("key1", expensive)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if want, have := 1, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	// First call on a new key SHOULD NOT be cached
	result, err = Do("key2", expensive)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if want, have := 2, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}
}

func TestSuccessCall(t *testing.T) {
	do := makeDoer(new(sync.Map))

	expensiveCalls := 0

	// Function tracks how many times its been called
	expensive := func() (interface{}, error) {
		expensiveCalls++
		return expensiveCalls, nil
	}

	// First call SHOULD NOT be cached
	result, err, cached := do("key1", expensive)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if want, have := 1, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	if want, have := false, cached; want != have {
		t.Fatalf("unexpected caching, want %t, have %t", want, have)
	}

	// Second call on same key SHOULD be cached
	result, err, cached = do("key1", expensive)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if want, have := 1, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	if want, have := true, cached; want != have {
		t.Fatalf("unexpected caching, want %t, have %t", want, have)
	}

	// First call on a new key SHOULD NOT be cached
	result, err, cached = do("key2", expensive)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if want, have := 2, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	if want, have := false, cached; want != have {
		t.Fatalf("unexpected caching, want %t, have %t", want, have)
	}
}

func TestFailedCall(t *testing.T) {
	do := makeDoer(new(sync.Map))

	calls := 0

	// This function will fail IFF it has not been called before.
	twoForTheMoney := func() (interface{}, error) {
		calls++

		if calls == 1 {
			return calls, errors.New("Try again")
		} else {
			return calls, nil
		}
	}

	// First call should fail, and not be cached
	result, err, cached := do("key1", twoForTheMoney)
	if err == nil {
		t.Fatalf("expected error")
	}

	if want, have := 1, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	if want, have := false, cached; want != have {
		t.Fatalf("unexpected caching, want %t, have %t", want, have)
	}

	// Second call should succeed, and not be cached
	result, err, cached = do("key1", twoForTheMoney)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if want, have := 2, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	if want, have := false, cached; want != have {
		t.Fatalf("unexpected caching, want %t, have %t", want, have)
	}

	// Third call should succeed, and be cached
	result, err, cached = do("key1", twoForTheMoney)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if want, have := 2, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	if want, have := true, cached; want != have {
		t.Fatalf("unexpected caching, want %t, have %t", want, have)
	}
}
