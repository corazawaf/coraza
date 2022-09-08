// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"context"
	"fmt"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestPmFromDataset(t *testing.T) {
	pm := &pmFromDataset{}
	opts := coraza.RuleOperatorOptions{
		Arguments: "test_1",
		Datasets: map[string][]string{
			"test_1": {"test_1", "test_2"},
		},
	}

	if err := pm.Init(opts); err != nil {
		t.Error(err)
	}
	waf := coraza.NewWAF()
	tx := waf.NewTransaction(context.Background())
	tx.Capture = true
	res := pm.Evaluate(tx, "test_1")
	if !res {
		t.Error("pmFromDataset failed")
	}
	opts.Datasets = map[string][]string{}
	if err := pm.Init(opts); err == nil {
		t.Error(fmt.Errorf("pmFromDataset should have failed"))
	}
}
