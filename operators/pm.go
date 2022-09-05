// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
)

// TODO according to coraza researchs, re2 matching is faster than ahocorasick
// maybe we should switch in the future
// pm is always lowercase
type pm struct {
	matcher ahocorasick.AhoCorasick
}

func (o *pm) Init(options corazawaf.RuleOperatorOptions) error {
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

func (o *pm) Evaluate(tx *corazawaf.Transaction, value string) bool {
	if tx.Capture {
		matches := o.matcher.FindAll(value)
		for i, match := range matches {
			if i == 10 {
				return true
			}
			tx.CaptureField(i, value[match.Start():match.End()])
		}
		return len(matches) > 0
	}
	iter := o.matcher.Iter(value)
	return iter.Next() != nil
}

var _ corazawaf.RuleOperator = (*pm)(nil)
