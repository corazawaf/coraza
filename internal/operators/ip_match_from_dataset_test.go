// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	_ "fmt"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/stretchr/testify/require"
)

func TestIpMatchFromDataset(t *testing.T) {
	addrok := []string{"127.0.0.1", "192.168.0.1", "192.168.0.253"}
	addrfail := []string{"127.0.0.2", "192.168.1.1"}

	opts := plugintypes.OperatorOptions{
		Arguments: "test_1",
		Datasets: map[string][]string{
			"test_1": {"127.0.0.1", "192.168.0.0/24"},
		},
	}

	ipm, err := newIPMatchFromDataset(opts)
	require.NoError(t, err, "Cannot init ipmatchfromfile operator")
	for _, ok := range addrok {
		require.True(t, ipm.Evaluate(nil, ok), "Invalid result for single CIDR IpMatchFromDataset %q", ok)
	}

	for _, fail := range addrfail {
		require.False(t, ipm.Evaluate(nil, fail), "Invalid result for single CIDR IpMatchFromDataset %q", fail)
	}
}

func TestIpMatchFromEmptyDataset(t *testing.T) {
	opts := plugintypes.OperatorOptions{
		Arguments: "test_1",
		Datasets: map[string][]string{
			"test_1": {},
		},
	}
	_, err := newIPMatchFromDataset(opts)
	require.Error(t, err, "Empty dataset not checked")
}
