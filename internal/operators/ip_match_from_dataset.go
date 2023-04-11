// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.ipMatchFromDataset

package operators

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func newIPMatchFromDataset(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments
	dataset, ok := options.Datasets[data]
	if !ok || len(dataset) == 0 {
		return nil, fmt.Errorf("dataset %q not found", data)
	}

	datasetParsed := strings.Join(dataset, ",")

	opts := plugintypes.OperatorOptions{
		Arguments: datasetParsed,
	}
	return newIPMatch(opts)
}

func init() {
	Register("ipMatchFromDataset", newIPMatchFromDataset)
}
