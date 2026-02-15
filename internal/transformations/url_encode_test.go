// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: "helloWorld",
			want:  "helloWorld",
		},
		{
			input: "hello world",
			want:  "hello+world",
		},
		{
			input: "https://www.coraza.io",
			want:  "https%3a%2f%2fwww%2ecoraza%2eio",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := urlEncode(tt.input)
			require.NoError(t, err)
			if tt.input == tt.want && changed || tt.input != tt.want && !changed {
				require.Failf(t, "unexpected changed value", "input %q, have %q with changed %t", tt.input, have, changed)
			}
			require.Equal(t, tt.want, have)
		})
	}
}

func BenchmarkURLEncode(b *testing.B) {
	tests := []string{
		" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}",
		"ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ",
		"~", //nolint:staticcheck
		"Test Case",
	}
	for i := 0; i < b.N; i++ {
		for _, tt := range tests {
			b.Run(tt, func(b *testing.B) {
				for j := 0; j < b.N; j++ {
					_, _, err := urlEncode(tt)
					require.NoError(b, err)
				}
			})
		}
	}
}
