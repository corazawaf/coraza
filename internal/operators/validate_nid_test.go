// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestVaildateNid(t *testing.T) {
	notOk := []string{"cl11.111.111-1", "us16100407-2", "clc 12345", "uss 1234567"}
	for _, no := range notOk {
		opts := plugintypes.OperatorOptions{
			Arguments: no,
		}
		_, err := newValidateNID(opts)
		if err == nil {
			t.Errorf("Wrong valid data for %s", no)
		}
	}
}

func TestNidCl(t *testing.T) {
	ok := []string{"11.111.111-1", "16100407-3", "8.492.655-8", "84926558", "111111111", "5348281-3", "10727393-k", "10727393-K"}
	nok := []string{"11.111.111-k", "16100407-2", "8.492.655-7", "84926557", "111111112", "5348281-4"}
	for _, o := range ok {
		if !nidCl(o) {
			t.Errorf("Invalid NID CL for %s", o)
		}
	}

	for _, o := range nok {
		if nidCl(o) {
			t.Errorf("Valid NID CL for %s", o)
		}
	}
	if nidCl("") {
		t.Errorf("Valid NID CL for empty string")
	}
}

// TestNidUs is a table test of the pure nidUs check; the JSON fixtures in
// testdata are not a usable home because TestOperators skips every case.
func TestNidUs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "area 574", in: "574-57-8065", want: true},
		{name: "area 739", in: "739-12-3456", want: true},
		{name: "area 740 assigned since 2011", in: "740-12-3456", want: true},
		{name: "area 899 assigned since 2011", in: "899-12-3456", want: true},
		{name: "no dashes", in: "432198765", want: true},
		{name: "area 000", in: "000-09-9999", want: false},
		{name: "area 666", in: "666-12-3456", want: false},
		{name: "area 900", in: "900-12-3456", want: false},
		{name: "area 999", in: "999-12-3456", want: false},
		{name: "group 00", in: "219-00-9999", want: false},
		{name: "serial 0000", in: "219-09-0000", want: false},
		{name: "ascending sequence", in: "123-45-6789", want: false},
		{name: "repeated digit", in: "111-11-1111", want: false},
		{name: "too short", in: "219-09-999", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if have := nidUs(tt.in); have != tt.want {
				t.Errorf("nidUs(%q) = %t, want %t", tt.in, have, tt.want)
			}
		})
	}
}

func TestDigitToInt(t *testing.T) {
	if want, have := 0, digitToInt('0'); want != have {
		t.Errorf("unexpected conversion, want %d, have %d", want, have)
	}

	if want, have := 9, digitToInt('9'); want != have {
		t.Errorf("unexpected conversion, want %d, have %d", want, have)
	}
}
