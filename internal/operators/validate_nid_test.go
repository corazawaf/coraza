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

func TestDigitToInt(t *testing.T) {
	if want, have := 0, digitToInt('0'); want != have {
		t.Errorf("unexpected conversion, want %d, have %d", want, have)
	}

	if want, have := 9, digitToInt('9'); want != have {
		t.Errorf("unexpected conversion, want %d, have %d", want, have)
	}
}
