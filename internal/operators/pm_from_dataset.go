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

	m, _ := memoize.Do(data, func() (interface{}, error) { return builder.Build(dataset), nil })

	return &pm{matcher: m.(ahocorasick.AhoCorasick)}, nil
}
