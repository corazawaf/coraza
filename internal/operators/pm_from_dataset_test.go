// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/stretchr/testify/require"
)

func TestPmFromDataset(t *testing.T) {
	opts := plugintypes.OperatorOptions{
		Arguments: "test_1",
		Datasets: map[string][]string{
			"test_1": {"test_1", "test_2"},
		},
	}
	pm, err := newPMFromDataset(opts)
	require.NoError(t, err)
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()
	tx.Capture = true
	res := pm.Evaluate(tx, "test_1")
	require.True(t, res, "pmFromDataset failed")
	opts.Datasets = map[string][]string{}

	_, err = newPMFromDataset(opts)
	require.Error(t, err, "pmFromDataset should have failed")
}
