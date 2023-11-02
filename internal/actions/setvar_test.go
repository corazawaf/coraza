// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions_test

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/actions"
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
	a, err := actions.Get("setvar")
	if err != nil {
		t.Error("failed to get setvar action")
	}
	t.Run("no arguments", func(t *testing.T) {
		if err := a.Init(nil, ""); err == nil || err != actions.ErrMissingArguments {
			t.Error("expected error ErrMissingArguments")
		}
	})
	t.Run("non-map variable", func(t *testing.T) {
		if err := a.Init(&md{}, "PATH_INFO=test"); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("TX set ok", func(t *testing.T) {
		if err := a.Init(&md{}, "TX.some=test"); err != nil {
			t.Error(err)
		}
	})
	t.Run("SESSION without key should fail", func(t *testing.T) {
		if err := a.Init(&md{}, "SESSION=test"); err == nil {
			t.Error("expected error")
		}
	})
}
