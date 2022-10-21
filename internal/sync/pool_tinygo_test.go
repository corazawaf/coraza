// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package sync

import (
	"testing"
)

func TestNewPool(t *testing.T) {
	p := NewPool(func() interface{} {
		n := int(1)
		return &n
	})

	x, ok := p.Get().(*int)
	if !ok {
		t.Fatal("failed to cast got element")
		return
	}

	*x = 2
	p.Put(x)

	y := p.Get()
	if want, have := x, y; want != have {
		t.Errorf("unexpected pool value, want %p, have %p", want, have)
	}

	if want, have := 2, *(y.(*int)); want != have {
		t.Errorf("unexpected pool value, want: %d, have: %d", want, have)
	}
}
