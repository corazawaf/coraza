// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/corazawaf/coraza/v3"
)

// TODO according to coraza researchs, re2 matching is faster than ahocorasick
// maybe we should switch in the future
// pm is always lowercase
type pm struct {
	matcher ahocorasick.AhoCorasick
}

func (o *pm) Init(options coraza.RuleOperatorOptions) error {
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

func (o *pm) Evaluate(tx *coraza.Transaction, value string) bool {
	return pmEvaluate(o.matcher, tx, value)
}

var _ coraza.RuleOperator = (*pm)(nil)

func pmEvaluate(matcher ahocorasick.AhoCorasick, tx *coraza.Transaction, value string) bool {
	var numMatches int
	iter := matcher.Iter(value)

	for {
		m := iter.Next()
		if m == nil {
			break
		}
		numMatches++
		if !tx.Capture {
			// Not capturing so just one match is enough.
			break
		}
		tx.CaptureField(numMatches-1, value[m.Start():m.End()])
		if numMatches == 10 {
			break
		}
	}

	return numMatches > 0
}
