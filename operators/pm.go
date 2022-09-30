// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/corazawaf/coraza/v3/rules"
)

// TODO according to coraza researchs, re2 matching is faster than ahocorasick
// maybe we should switch in the future
// pm is always lowercase
type pm struct {
	matcher ahocorasick.AhoCorasick
}

var _ rules.Operator = (*pm)(nil)

func (o *pm) Init(options rules.OperatorOptions) error {
	data := options.Arguments

	data = strings.ToLower(data)
	dict := strings.Split(data, " ")
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  true,
	})

	// TODO this operator is supposed to support snort data syntax: "@pm A|42|C|44|F"
	o.matcher = builder.Build(dict)
	return nil
}

func (o *pm) Evaluate(tx rules.TransactionState, value string) bool {
	return pmEvaluate(o.matcher, tx, value)
}

func pmEvaluate(matcher ahocorasick.AhoCorasick, tx rules.TransactionState, value string) bool {
	iter := matcher.Iter(value)

	if !tx.Capturing() {
		// Not capturing so just one match is enough.
		return iter.Next() != nil
	}

	var numMatches int
	for {
		m := iter.Next()
		if m == nil {
			break
		}

		tx.CaptureField(numMatches, value[m.Start():m.End()])

		numMatches++
		if numMatches == 10 {
			return true
		}
	}

	return numMatches > 0
}
