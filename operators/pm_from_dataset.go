// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/corazawaf/coraza/v3/rules"
)

// TODO according to coraza researchs, re2 matching is faster than ahocorasick
// maybe we should switch in the future
// pmFromDataset is always lowercase
type pmFromDataset struct {
	matcher ahocorasick.AhoCorasick
}

var _ rules.Operator = (*pmFromDataset)(nil)

func (o *pmFromDataset) Init(options rules.OperatorOptions) error {
	data := options.Arguments
	dataset, ok := options.Datasets[data]
	if !ok {
		return fmt.Errorf("dataset %q not found", data)
	}
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  true,
	})

	o.matcher = builder.Build(dataset)
	return nil
}

func (o *pmFromDataset) Evaluate(tx rules.TransactionState, value string) bool {
	return pmEvaluate(o.matcher, tx, value)
}
