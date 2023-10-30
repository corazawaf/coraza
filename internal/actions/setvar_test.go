// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"bytes"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type md struct {
}

func (md) ID() int {
	return 0
}
func (md) ParentID() int {
	return 0
}
func (md) Status() int {
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

var invalidSyntaxAtoiError = "invalid syntax"
var warningKeyNotFoundInCollection = "key not found in collection"

func TestSetvarEvaluate(t *testing.T) {
	tests := []struct {
		name                     string
		init                     string
		init2                    string
		expectInvalidSyntaxError bool
		expectNewVarValue        string
	}{
		{
			name:                     "Numerical operation + with existing variable",
			init:                     "TX.var=5",
			init2:                    "TX.newvar=+%{tx.var}",
			expectInvalidSyntaxError: false,
			expectNewVarValue:        "5",
		},
		{
			name:                     "Numerical operation - with existing variable",
			init:                     "TX.var=5",
			init2:                    "TX.newvar=-%{tx.var}",
			expectInvalidSyntaxError: false,
			expectNewVarValue:        "-5",
		},
		{
			name:                     "Numerical operation - with existing negative variable",
			init:                     "TX.newvar=-5",
			init2:                    "TX.newvar=+5",
			expectInvalidSyntaxError: false,
			expectNewVarValue:        "0",
		},
		{
			name:                     "Numerical operation + with missing (or non-numerical) variable",
			init:                     "TX.newvar=+%{tx.missingvar}",
			expectInvalidSyntaxError: true,
		},
		{
			name:                     "Numerical operation - with missing (or non-numerical) variable",
			init:                     "TX.newvar=-%{tx.missingvar}",
			expectInvalidSyntaxError: true,
		},
	}

	for _, tt := range tests {
		logsBuf := &bytes.Buffer{}

		logger := debuglog.Default().WithLevel(debuglog.LevelWarn).WithOutput(logsBuf)

		t.Run(tt.name, func(t *testing.T) {
			defer logsBuf.Reset()
			a := setvar()
			metadata := &md{}
			if err := a.Init(metadata, tt.init); err != nil {
				t.Error("unexpected error during setvar init")
			}
			waf := corazawaf.NewWAF()
			waf.Logger = logger
			tx := waf.NewTransaction()
			a.Evaluate(metadata, tx)
			if tt.expectInvalidSyntaxError {
				if logsBuf.Len() == 0 {
					t.Fatal("expected error")
				}
				if !strings.Contains(logsBuf.String(), invalidSyntaxAtoiError) {
					t.Errorf("expected error containing %q, got %q", invalidSyntaxAtoiError, logsBuf.String())
				}
				if !strings.Contains(logsBuf.String(), warningKeyNotFoundInCollection) {
					t.Errorf("expected error containing %q, got %q", warningKeyNotFoundInCollection, logsBuf.String())
				}
			}
			if logsBuf.Len() != 0 && !tt.expectInvalidSyntaxError {
				t.Fatalf("unexpected error: %s", logsBuf.String())
			}

			if tt.init2 != "" {
				if err := a.Init(metadata, tt.init2); err != nil {
					t.Fatal("unexpected error during setvar init")
				}
				a.Evaluate(metadata, tx)
				if logsBuf.Len() != 0 && !tt.expectInvalidSyntaxError {
					t.Fatalf("unexpected error: %s", logsBuf.String())
				}
			}
			if tt.expectNewVarValue != "" {
				checkCollectionValue(t, a.(*setvarFn), tx, "newvar", tt.expectNewVarValue)
			}
		})
	}
}

func checkCollectionValue(t *testing.T, a *setvarFn, tx plugintypes.TransactionState, key string, expected string) {
	t.Helper()
	var col collection.Map
	if c, ok := tx.Collection(a.collection).(collection.Map); !ok {
		t.Fatal("collection in setvar is not a map")
		return
	} else {
		col = c
	}
	if col == nil {
		t.Fatal("collection in setvar is nil")
		return
	}
	if col == nil {
		t.Fatal("collection is nil")
	}
	if col.Get(key)[0] != expected {
		t.Errorf("key %q: expected %q, got %q", key, expected, col.Get(key))
	}
}
