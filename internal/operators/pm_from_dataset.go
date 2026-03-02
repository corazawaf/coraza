// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.pmFromDataset

package operators

import (
	"fmt"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/memoize"
)

// Description:
// Performs case-insensitive pattern matching like @pmFromFile but uses an in-memory dataset
// instead of reading from a file. The dataset must be provided at WAF initialization time.
// Uses the Aho-Corasick algorithm for efficient multi-pattern matching.
//
// Arguments:
// Name of the dataset to use for matching. The dataset must be pre-configured and available.
//
// Returns:
// true if any pattern from the dataset is found in the input, false otherwise
//
// Example:
// ```
// # Match against pre-loaded dataset
// SecRule REQUEST_URI "@pmFromDataset blocked_paths" "id:174,deny,log"
//
// # Check user agent against known bot dataset
// SecRule REQUEST_HEADERS:User-Agent "@pmFromDataset bot_signatures" "id:175,deny"
// ```
func newPMFromDataset(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments
	dataset, ok := options.Datasets[data]
	if !ok {
		return nil, fmt.Errorf("dataset %q not found", data)
	}
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  true,
	})

	m, _ := memoize.Do(data, func() (any, error) { return builder.Build(dataset), nil })

	return &pm{matcher: m.(ahocorasick.AhoCorasick)}, nil
}

func init() {
	Register("pmFromDataset", newPMFromDataset)
}
