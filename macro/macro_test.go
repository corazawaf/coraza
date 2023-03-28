// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package macro

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestNewMacro(t *testing.T) {
	_, err := NewMacro("")
	if err == nil {
		t.Errorf("expected error: %s", errEmptyData.Error())
	}

	_, err = NewMacro("some string")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	_, err = NewMacro("%{}")
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestCompile(t *testing.T) {
	t.Run("empty data", func(t *testing.T) {
		m := &macro{}
		err := m.compile("")
		if err == nil || err.Error() != "empty macro" {
			t.Errorf("expected error: empty macro")
		}
	})

	t.Run("malformed macro", func(t *testing.T) {
		for _, test := range []string{"%{tx.count", "%{{tx.count}", "%{{tx.{count}", "something %{tx.count"} {
			t.Run(test, func(t *testing.T) {
				m := &macro{}
				err := m.compile(test)
				if err == nil {
					t.Fatalf("expected error")
				}

				expectedErr := "malformed variable"
				if err != nil && !strings.Contains(err.Error(), expectedErr) {
					t.Errorf("unexpected error, expected to contain %q, got %q", expectedErr, err.Error())
				}
			})
		}
	})

	t.Run("unknown variable", func(t *testing.T) {
		m := &macro{}

		err := m.compile("%{unknown_variable.x}")
		if err == nil {
			t.Fatalf("expected error")
		}

		expectedErr := "unknown variable"
		if !strings.Contains(err.Error(), expectedErr) {
			t.Errorf("unexpected error, should contain %q, got %q", expectedErr, err.Error())
		}
	})

	t.Run("valid macro", func(t *testing.T) {
		m := &macro{}
		err := m.compile("%{tx.count}")
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}

		if want, have := 1, len(m.tokens); want != have {
			t.Fatalf("unexpected number of tokens: want %d, have %d", want, have)
		}

		expectedMacro := macroToken{"tx.count", variables.TX, "count"}
		if want, have := m.tokens[0], expectedMacro; want != have {
			t.Errorf("unexpected token: want %v, have %v", want, have)
		}
	})

	t.Run("multi variable", func(t *testing.T) {
		m := &macro{}
		err := m.compile("%{tx.id} got %{tx.count} in this transaction and as zero %{tx.0}")
		if err != nil {
			t.Errorf("unexpected error: %s", err.Error())
		}

		if want, have := 5, len(m.tokens); want != have {
			t.Fatalf("unexpected number of tokens: want %d, have %d", want, have)
		}

		expectedMacro0 := macroToken{"tx.id", variables.TX, "id"}
		if want, have := m.tokens[0], expectedMacro0; want != have {
			t.Errorf("unexpected token: want %v, have %v", want, have)
		}

		expectedMacro1 := macroToken{" got ", variables.Unknown, ""}
		if want, have := m.tokens[1], expectedMacro1; want != have {
			t.Errorf("unexpected token: want %v, have %v", want, have)
		}

		expectedMacro2 := macroToken{"tx.count", variables.TX, "count"}
		if want, have := m.tokens[2], expectedMacro2; want != have {
			t.Errorf("unexpected token: want %v, have %v", want, have)
		}

		expectedMacro3 := macroToken{" in this transaction and as zero ", variables.Unknown, ""}
		if want, have := m.tokens[3], expectedMacro3; want != have {
			t.Errorf("unexpected token: want %v, have %v", want, have)
		}

		expectedMacro4 := macroToken{"tx.0", variables.TX, "0"}
		if want, have := m.tokens[4], expectedMacro4; want != have {
			t.Errorf("unexpected token: want %v, have %v", want, have)
		}
	})
}

func TestExpand(t *testing.T) {
	t.Run("no expansion", func(t *testing.T) {
		m := &macro{
			tokens: []macroToken{
				{"text", variables.Unknown, ""},
			},
		}

		if want, have := "text", m.Expand(nil); want != have {
			t.Errorf("unexpected expansion: want %q, have %q", want, have)
		}
	})
}
