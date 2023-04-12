// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.ipMatchFromFile

package operators

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func newIPMatchFromFile(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	path := options.Arguments

	data, err := loadFromFile(path, options.Path, options.Root)
	if err != nil {
		return nil, err
	}

	dataParsed := strings.Builder{}
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
		dataParsed.WriteString(",")
		dataParsed.WriteString(l)
	}

	opts := plugintypes.OperatorOptions{
		Arguments: dataParsed.String(),
	}
	return newIPMatch(opts)
}

func init() {
	Register("ipMatchFromFile", newIPMatchFromFile)
}
