// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestPmFromDataset(t *testing.T) {
	opts := plugintypes.OperatorOptions{
		Arguments: "test_1",
		Datasets: map[string][]string{
			"test_1": {"test_1", "test_2"},
		},
	}
	pm, err := newPMFromDataset(opts)
	if err != nil {
		t.Error(err)
	}
	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()
	tx.Capture = true
	res := pm.Evaluate(tx, "test_1")
	if !res {
		t.Error("pmFromDataset failed")
	}
	opts.Datasets = map[string][]string{}

	if _, err = newPMFromDataset(opts); err == nil {
		t.Error(fmt.Errorf("pmFromDataset should have failed"))
	}
}
