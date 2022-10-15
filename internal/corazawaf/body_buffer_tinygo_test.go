// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package corazawaf

import (
	"testing"

	"github.com/corazawaf/coraza/v3/types"
)

func TestWriteOverLimit(t *testing.T) {
	br := NewBodyBuffer(types.BodyBufferOptions{
		MemoryLimit: 2,
	})
	defer br.Close()
	n, err := br.Write([]byte{'a', 'b', 'c'})
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if want, have := 2, n; want != have {
		t.Errorf("unexpected number of bytes in write, want: %d, have: %d", want, have)
	}

	if want, have := "ab", br.buffer.String(); want != have {
		t.Errorf("unexpected writen bytes, want: %q, have: %q", want, have)
	}
}
