// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package auditlog

import (
	"reflect"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
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

func TestRegisterAndGetWriter(t *testing.T) {

	testCases := []struct {
		name string
	}{
		{"customwriter"},
		{"CustomWriter"},
		{"CUSTOMWRITER"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			RegisterWriter(tc.name, func() plugintypes.AuditLogWriter {
				return noopWriter{}
			})

			writer, err := GetWriter(tc.name)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if writer == nil {
				t.Fatalf("expected a writer, got nil")
			}
		})
	}
}

func TestRegisterAndGetFormatter(t *testing.T) {

	testCases := []struct {
		name string
	}{
		{"customFormatter"},
		{"customformatter"},
		{"CUSTOMFORMATTER"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			RegisterFormatter(tc.name, &noopFormatter{})
			retrievedFormatter, err := GetFormatter(tc.name)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if retrievedFormatter == nil {
				t.Fatalf("expected a formatter, got nil")
			}
		})
	}
}
