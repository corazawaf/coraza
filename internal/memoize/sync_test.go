// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.no_memoize

package memoize

import (
	"errors"
	"testing"
)

func TestDo(t *testing.T) {
	m := NewMemoizer()
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
	m := NewMemoizer()
	calls := 0

	twoForTheMoney := func() (any, error) {
		calls++
		if calls == 1 {
			return calls, errors.New("Try again")
		}
		return calls, nil
	}

	result, err := m.Do("failkey1", twoForTheMoney)
	if err == nil {
		t.Fatalf("expected error")
	}
	if want, have := 1, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	result, err = m.Do("failkey1", twoForTheMoney)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 2, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	result, err = m.Do("failkey1", twoForTheMoney)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 2, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}
}
