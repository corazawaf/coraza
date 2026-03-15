// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.no_memoize

package memoize

import (
	"errors"
	"strconv"
	"testing"
)

func TestNoopDo(t *testing.T) {
	m := NewMemoizer(1)
	calls := 0

	fn := func() (any, error) {
		calls++
		return calls, nil
	}

	result, err := m.Do("key1", fn)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 1, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	// No-op memoizer should call fn again (no caching).
	result, err = m.Do("key1", fn)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 2, result.(int); want != have {
		t.Fatalf("expected no caching, want %d, have %d", want, have)
	}
}

func TestNoopDoError(t *testing.T) {
	m := NewMemoizer(1)

	_, err := m.Do("key1", func() (any, error) {
		return nil, errors.New("fail")
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestNoopDoMultipleKeys verifies that different keys each invoke fn independently.
func TestNoopDoMultipleKeys(t *testing.T) {
	m := NewMemoizer(1)
	calls := 0

	fn := func() (any, error) {
		calls++
		return calls, nil
	}

	for i := 1; i <= 3; i++ {
		result, err := m.Do("key"+strconv.Itoa(i), fn)
		if err != nil {
			t.Fatalf("unexpected error on key %d: %s", i, err.Error())
		}
		if want, have := i, result.(int); want != have {
			t.Fatalf("key%d: want %d, have %d", i, want, have)
		}
	}
	if calls != 3 {
		t.Fatalf("expected 3 fn calls, got %d", calls)
	}
}

// TestNoopErrorNotCached verifies that errors returned by fn are not cached:
// a subsequent call with the same key will invoke fn again.
func TestNoopErrorNotCached(t *testing.T) {
	m := NewMemoizer(1)
	calls := 0

	fn := func() (any, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("transient error")
		}
		return calls, nil
	}

	// First call should return error.
	_, err := m.Do("key1", fn)
	if err == nil {
		t.Fatal("expected error on first call")
	}

	// Second call should succeed (no caching of error).
	result, err := m.Do("key1", fn)
	if err != nil {
		t.Fatalf("unexpected error on second call: %s", err.Error())
	}
	if want, have := 2, result.(int); want != have {
		t.Fatalf("want %d, have %d", want, have)
	}

	// Third call: fn invoked again (still no caching).
	result, err = m.Do("key1", fn)
	if err != nil {
		t.Fatalf("unexpected error on third call: %s", err.Error())
	}
	if want, have := 3, result.(int); want != have {
		t.Fatalf("want %d, have %d", want, have)
	}
}

// TestNoopRelease verifies that Release is a no-op and does not panic or affect subsequent Do calls.
func TestNoopRelease(t *testing.T) {
	m := NewMemoizer(1)
	calls := 0

	fn := func() (any, error) {
		calls++
		return calls, nil
	}

	result, err := m.Do("key1", fn)
	if err != nil {
		t.Fatalf("unexpected error before Release: %s", err.Error())
	}
	if want, have := 1, result.(int); want != have {
		t.Fatalf("before Release: want %d, have %d", want, have)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call before Release, got %d", calls)
	}

	// Release should not panic and should be a no-op.
	Release(1)

	// Subsequent calls should still work normally.
	result, err = m.Do("key1", fn)
	if err != nil {
		t.Fatalf("unexpected error after Release: %s", err.Error())
	}
	if want, have := 2, result.(int); want != have {
		t.Fatalf("expected fn called again after Release, want %d, have %d", want, have)
	}
}

// TestNoopReset verifies that Reset is a no-op and does not panic or affect subsequent Do calls.
func TestNoopReset(t *testing.T) {
	m := NewMemoizer(1)
	calls := 0

	fn := func() (any, error) {
		calls++
		return calls, nil
	}

	for _, key := range []string{"k1", "k2"} {
		result, err := m.Do(key, fn)
		if err != nil {
			t.Fatalf("unexpected error for %s before Reset: %s", key, err.Error())
		}
		if result == nil {
			t.Fatalf("unexpected nil result for %s", key)
		}
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls before Reset, got %d", calls)
	}

	// Reset should not panic.
	Reset()

	// Calls after Reset should continue working.
	result, err := m.Do("k1", fn)
	if err != nil {
		t.Fatalf("unexpected error after Reset: %s", err.Error())
	}
	if want, have := 3, result.(int); want != have {
		t.Fatalf("expected fn called again after Reset, want %d, have %d", want, have)
	}
}

// TestNoopMultipleMemoizers verifies that multiple no-op memoizers are independent
// (no shared state between different owner IDs).
func TestNoopMultipleMemoizers(t *testing.T) {
	m1 := NewMemoizer(1)
	m2 := NewMemoizer(2)
	calls := 0

	fn := func() (any, error) {
		calls++
		return calls, nil
	}

	r1, _ := m1.Do("shared", fn)
	r2, _ := m2.Do("shared", fn)

	if r1.(int) != 1 || r2.(int) != 2 {
		t.Fatalf("expected independent calls: m1=%d, m2=%d", r1.(int), r2.(int))
	}
	if calls != 2 {
		t.Fatalf("expected 2 fn calls, got %d", calls)
	}
}
