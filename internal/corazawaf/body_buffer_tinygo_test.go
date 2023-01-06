// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package corazawaf

import (
	"testing"

	"github.com/corazawaf/coraza/v3/types"
)

func TestTinyGoWriteOverLimit(t *testing.T) {
	testCases := []struct {
		name               string
		wantedWrittenBytes string
		discardOnBodyLimit bool
	}{
		{
			name:               "when Rejecting",
			wantedWrittenBytes: "",
			discardOnBodyLimit: true,
		},
		{
			name:               "when Process Partial",
			wantedWrittenBytes: "ab",
			discardOnBodyLimit: false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			br := NewBodyBuffer(types.BodyBufferOptions{
				MemoryLimit:        2,
				DiscardOnBodyLimit: testCase.discardOnBodyLimit,
			})
			defer br.Reset()
			n, err := br.Write([]byte{'a', 'b', 'c'})
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}

			if want, have := len(testCase.wantedWrittenBytes), n; want != have {
				t.Errorf("unexpected number of bytes in write, want: %d, have: %d", want, have)
			}

			if want, have := testCase.wantedWrittenBytes, br.buffer.String(); want != have {
				t.Errorf("unexpected writen bytes, want: %q, have: %q", want, have)
			}
		})
	}
}
