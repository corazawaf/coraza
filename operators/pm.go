// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3"
	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
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
	if tx.Capture {
		matches := o.matcher.FindAll(value)
		for i, match := range matches {
			if i == 10 {
				return true
			}
			tx.CaptureField(i, value[match.Start():match.End()])
		}
		return len(matches) > 0
	} else {
		iter := o.matcher.Iter(value)
		return iter.Next() != nil
	}
}

var _ coraza.RuleOperator = (*pm)(nil)
