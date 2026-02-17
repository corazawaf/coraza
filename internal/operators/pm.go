// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.pm

package operators

import (
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/memoize"
)

// Description:
// Performs case-insensitive pattern matching using the Aho-Corasick algorithm for efficient
// multi-pattern searching. Matches space-separated keywords or patterns provided as arguments.
//
// Arguments:
// Space-separated keywords or patterns to match. Supports Snort data syntax like "A|42|C|44|F"
// for hex notation. All patterns are converted to lowercase for case-insensitive matching.
//
// Returns:
// true if any of the patterns are found in the input, false otherwise
//
// Example:
// ```
// # Detect known malicious user agents
// SecRule REQUEST_HEADERS:User-Agent "@pm WebZIP WebCopier Webster" "id:170,deny,log"
//
// # Match multiple attack patterns
// SecRule ARGS "@pm <script> javascript: onerror=" "id:171,deny"
// ```
type pm struct {
	matcher ahocorasick.AhoCorasick
}

var _ plugintypes.Operator = (*pm)(nil)

func newPM(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	data = strings.ToLower(data)
	dict := strings.Split(data, " ")
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  true,
	})

	m, _ := memoize.Do(data, func() (any, error) { return builder.Build(dict), nil })
	// TODO this operator is supposed to support snort data syntax: "@pm A|42|C|44|F"
	return &pm{matcher: m.(ahocorasick.AhoCorasick)}, nil
}

func (o *pm) Evaluate(tx plugintypes.TransactionState, value string) bool {
	return pmEvaluate(o.matcher, tx, value)
}

func pmEvaluate(matcher ahocorasick.AhoCorasick, tx plugintypes.TransactionState, value string) bool {
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

func init() {
	Register("pm", newPM)
}
