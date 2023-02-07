// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestSingle(t *testing.T) {
	c := NewSingle(variables.ArgsPath)

	if want, have := "ARGS_PATH", c.Name(); want != have {
		t.Errorf("want %s, have %s", want, have)
	}

	if want, have := "", c.Get(); want != have {
		t.Errorf("want %s, have %s", want, have)
	}

	if want, have := "ARGS_PATH: ", c.String(); want != have {
		t.Errorf("want %s, have %s", want, have)
	}

	assertValuesMatch(t, c.FindAll())

	c.Set("bear")

	if want, have := "bear", c.Get(); want != have {
		t.Errorf("want %s, have %s", want, have)
	}

	if want, have := "ARGS_PATH: bear", c.String(); want != have {
		t.Errorf("want %s, have %s", want, have)
	}

	assertValuesMatch(t, c.FindAll(), "bear")
}
