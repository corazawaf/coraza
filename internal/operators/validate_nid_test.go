// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/stretchr/testify/require"
)

func TestVaildateNid(t *testing.T) {
	notOk := []string{"cl11.111.111-1", "us16100407-2", "clc 12345", "uss 1234567"}
	for _, no := range notOk {
		opts := plugintypes.OperatorOptions{
			Arguments: no,
		}
		_, err := newValidateNID(opts)
		require.Error(t, err, "Wrong valid data for %s", no)
	}
}

func TestNidCl(t *testing.T) {
	ok := []string{"11.111.111-1", "16100407-3", "8.492.655-8", "84926558", "111111111", "5348281-3", "10727393-k", "10727393-K"}
	nok := []string{"11.111.111-k", "16100407-2", "8.492.655-7", "84926557", "111111112", "5348281-4"}
	for _, o := range ok {
		require.True(t, nidCl(o), "Invalid NID CL for %s", o)
	}

	for _, o := range nok {
		require.False(t, nidCl(o), "Valid NID CL for %s", o)
	}
	require.False(t, nidCl(""), "Valid NID CL for empty string")
}

func TestDigitToInt(t *testing.T) {
	require.Equal(t, 0, digitToInt('0'), "unexpected conversion")

	require.Equal(t, 9, digitToInt('9'), "unexpected conversion")
}
