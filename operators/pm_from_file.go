// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.pmFromFile

package operators

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/rules"
)

func newPMFromFile(options rules.OperatorOptions) (rules.Operator, error) {
	path := options.Arguments

	data, err := loadFromFile(path, options.Path, options.Root)
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

	patterns := strings.Join(lines[:], "|")

	return &pm{matcher: regexp.MustCompile(patterns)}, nil
}

func init() {
	Register("pmFromFile", newPMFromFile)
}
