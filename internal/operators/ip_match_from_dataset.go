// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.ipMatchFromDataset

package operators

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Performs IPv4/IPv6 address matching like @ipMatchFromFile but uses an in-memory dataset
// instead of reading from a file. The dataset must be provided at WAF initialization time.
// Supports CIDR notation for IP ranges.
//
// Arguments:
// Name of the dataset to use for matching. The dataset must be pre-configured and available.
//
// Returns:
// true if the input IP address matches any IP or range in the dataset, false otherwise
//
// Example:
// ```
// # Match against pre-loaded IP dataset
// SecRule REMOTE_ADDR "@ipMatchFromDataset blocked_ips" "id:168,deny,log"
//
// # Check against trusted proxy list
// SecRule REMOTE_ADDR "@ipMatchFromDataset trusted_proxies" "id:169,pass"
// ```
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
