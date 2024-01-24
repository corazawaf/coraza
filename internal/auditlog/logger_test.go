// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

import (
	"reflect"
	"testing"

	"github.com/corazawaf/coraza/v4/experimental/plugins/plugintypes"
)

func TestDefaultWriters(t *testing.T) {
	ws := []string{"serial", "concurrent"}
	for _, writer := range ws {
		if w, err := GetWriter(writer); err != nil {
			t.Error(err)
		} else if w == nil {
			t.Errorf("invalid %s writer", writer)
		}
	}
}

func TestGetUnknownWriter(t *testing.T) {
	if _, err := GetWriter("unknown"); err == nil {
		t.Error("expected error")
	}
}

type noopFormatter struct{}

func (noopFormatter) Format(al plugintypes.AuditLog) ([]byte, error) { return nil, nil }
func (noopFormatter) MIME() string                                   { return "" }

func TestGetFormatters(t *testing.T) {
	t.Run("missing formatter", func(t *testing.T) {
		if _, err := GetFormatter("missing"); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("existing formatter", func(t *testing.T) {
		f := &noopFormatter{}
		RegisterFormatter("test", f)
		actualFn, err := GetFormatter("TeSt")
		if err != nil {
			t.Errorf("unexpected error: %s", err.Error())
		}

		if want, have := reflect.ValueOf(f), reflect.ValueOf(actualFn); want.Pointer() != have.Pointer() {
			t.Errorf("unexpected formatter function")
		}
	})
}
