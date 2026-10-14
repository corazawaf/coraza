// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package strings

import (
	"bytes"
	"testing"
	"unsafe"
)

func TestUnsafeBytes(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"one byte", "a"},
		{"ascii", "select * from users"},
		{"multibyte", "héllo wörld ☃"},
		{"nul and high bytes", "a\x00b\xffc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := UnsafeBytes(tc.in)
			if !bytes.Equal(got, []byte(tc.in)) {
				t.Fatalf("UnsafeBytes(%q) = %q", tc.in, got)
			}
			if len(got) != len(tc.in) || cap(got) != len(tc.in) {
				t.Errorf("len/cap = %d/%d, want %d/%d: an append must reallocate, not write into the string",
					len(got), cap(got), len(tc.in), len(tc.in))
			}
			if len(tc.in) > 0 && unsafe.SliceData(got) != unsafe.StringData(tc.in) {
				t.Error("the slice does not alias the string: the value was copied")
			}
		})
	}
}
