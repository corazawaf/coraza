// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.pmFromFile

package operators

import (
	"bufio"
	"bytes"
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/memoize"
)

func newPMFromFile(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	filepath := options.Arguments

	data, err := loadFromFile(filepath, options.Path, options.Root)
	if err != nil {
		return nil, err
	}

	var lines []string
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

	m, _ := memoize.Do(strings.Join(options.Path, ",")+filepath, func() (any, error) { return builder.Build(lines), nil })

	return &pm{matcher: m.(ahocorasick.AhoCorasick)}, nil
}

func init() {
	Register("pmFromFile", newPMFromFile)
	Register("pmf", newPMFromFile)
}
