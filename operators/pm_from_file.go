// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"bufio"
	"bytes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
)

type pmFromFile struct {
	matcher ahocorasick.AhoCorasick
}

func (o *pmFromFile) Init(options corazawaf.RuleOperatorOptions) error {
	path := options.Arguments

	data, err := loadFromFile(path, options.Path)
	if err != nil {
		return err
	}

	lines := []string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		l := sc.Text()
		l = strings.TrimSpace(l)
		if len(l) == 0 {
			continue
		}
		if l[0] == '#' {
			continue
		}
		lines = append(lines, strings.ToLower(l))
	}

	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  false,
	})

	o.matcher = builder.Build(lines)
	return nil
}

func (o *pmFromFile) Evaluate(tx *corazawaf.Transaction, value string) bool {
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

var _ corazawaf.RuleOperator = (*pmFromFile)(nil)
