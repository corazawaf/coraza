// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.no_memoize

package memoize

import (
	"errors"
	"testing"
)

func TestNoopDo(t *testing.T) {
	m := NewMemoizer()
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
	m := NewMemoizer()

	_, err := m.Do("key1", func() (any, error) {
		return nil, errors.New("fail")
	})
	if err == nil {
		t.Fatal("expected error")
	}
}
