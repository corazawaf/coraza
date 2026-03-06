// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.no_memoize

package memoize

import (
	"errors"
	"testing"
)

func TestDo(t *testing.T) {
	t.Cleanup(Reset)

	m := NewMemoizer("test")
	expensiveCalls := 0

	expensive := func() (any, error) {
		expensiveCalls++
		return expensiveCalls, nil
	}

	result, err := m.Do("key1", expensive)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 1, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	result, err = m.Do("key1", expensive)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 1, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	result, err = m.Do("key2", expensive)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 2, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}
}

func TestFailedCall(t *testing.T) {
	t.Cleanup(Reset)

	m := NewMemoizer("test")
	calls := 0

	twoForTheMoney := func() (any, error) {
		calls++
		if calls == 1 {
			return calls, errors.New("Try again")
		}
		return calls, nil
	}

	result, err := m.Do("key1", twoForTheMoney)
	if err == nil {
		t.Fatalf("expected error")
	}
	if want, have := 1, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	result, err = m.Do("key1", twoForTheMoney)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 2, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	result, err = m.Do("key1", twoForTheMoney)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 2, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}
}

func TestRelease(t *testing.T) {
	t.Cleanup(Reset)

	m1 := NewMemoizer("waf-1")
	m2 := NewMemoizer("waf-2")

	calls := 0
	fn := func() (any, error) {
		calls++
		return calls, nil
	}

	_, _ = m1.Do("shared", fn)
	_, _ = m2.Do("shared", fn)
	_, _ = m1.Do("only-waf1", fn)

	Release("waf-1")

	if _, ok := cache.Load("shared"); !ok {
		t.Fatal("shared entry should still exist after releasing waf-1")
	}
	if _, ok := cache.Load("only-waf1"); ok {
		t.Fatal("only-waf1 entry should be deleted after releasing its sole owner")
	}

	Release("waf-2")
	if _, ok := cache.Load("shared"); ok {
		t.Fatal("shared entry should be deleted after releasing all owners")
	}
}

func TestReset(t *testing.T) {
	m := NewMemoizer("test")
	_, _ = m.Do("k1", func() (any, error) { return 1, nil })
	_, _ = m.Do("k2", func() (any, error) { return 2, nil })

	Reset()

	if _, ok := cache.Load("k1"); ok {
		t.Fatal("cache should be empty after Reset")
	}
	if _, ok := cache.Load("k2"); ok {
		t.Fatal("cache should be empty after Reset")
	}
}
