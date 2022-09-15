// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"bufio"
	"bytes"
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/corazawaf/coraza/v3"
)

type pmFromFile struct {
	matcher ahocorasick.AhoCorasick
}

var _ coraza.RuleOperator = (*pmFromFile)(nil)

func (o *pmFromFile) Init(options coraza.RuleOperatorOptions) error {
	path := options.Arguments

	data, err := loadFromFile(path, options.Path, options.Root)
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

func (o *pmFromFile) Evaluate(tx *coraza.Transaction, value string) bool {
	return pmEvaluate(o.matcher, tx, value)
}
