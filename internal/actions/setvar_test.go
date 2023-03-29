// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"
)

type md struct {
}

func (_ md) ID() int {
	return 0
}
func (_ md) ParentID() int {
	return 0
}
func (_ md) Status() int {
	return 0
}

func TestSetvarInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := setvar()
		if err := a.Init(nil, ""); err == nil || err != ErrMissingArguments {
			t.Error("expected error ErrMissingArguments")
		}
	})
	t.Run("non-map variable", func(t *testing.T) {
		a := setvar()
		if err := a.Init(&md{}, "PATH_INFO=test"); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("TX set ok", func(t *testing.T) {
		a := setvar()
		if err := a.Init(&md{}, "TX.some=test"); err != nil {
			t.Error(err)
		}
	})
	t.Run("TX without key should fail", func(t *testing.T) {
		a := setvar()
		if err := a.Init(&md{}, "TX=test"); err == nil {
			t.Error("expected error")
		}
	})
}
