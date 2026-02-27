// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	_ "fmt"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/stretchr/testify/require"
)

func TestOneAddress(t *testing.T) {
	addrok := "127.0.0.1"
	addrfail := "127.0.0.2"
	cidr := "127.0.0.1/32"
	opts := plugintypes.OperatorOptions{
		Arguments: cidr,
	}
	ipm, err := newIPMatch(opts)
	require.NoError(t, err, "Cannot init ipmatchtest operator")
	require.True(t, ipm.Evaluate(nil, addrok), "Invalid result for single CIDR IpMatch")
	require.False(t, ipm.Evaluate(nil, addrfail), "Invalid result for single CIDR IpMatch")
}

func TestMultipleAddress(t *testing.T) {
	addrok := []string{"127.0.0.1", "192.168.0.1", "192.168.0.253"}
	addrfail := []string{"127.0.0.2", "192.168.1.1"}
	cidr := "127.0.0.1, 192.168.0.0/24"
	opts := plugintypes.OperatorOptions{
		Arguments: cidr,
	}
	ipm, err := newIPMatch(opts)
	require.NoError(t, err, "Cannot init ipmatchtest operator")
	for _, ok := range addrok {
		require.True(t, ipm.Evaluate(nil, ok), "Invalid result for single CIDR IpMatch: %s", ok)
	}

	for _, fail := range addrfail {
		require.False(t, ipm.Evaluate(nil, fail), "Invalid result for single CIDR IpMatch: %s", fail)
	}
}
