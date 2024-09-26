// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/redwanghb/coraza/v3/internal/corazawaf"
)

var sqliTests = []string{
	"",
	"this is not isqli",
	"ascii(substring(version() from 1 for 1))",
	"this\nis a ' or ''='\nsql injection",
}

func FuzzSQLi(f *testing.F) {
	for _, tc := range sqliTests {
		f.Add(tc)
	}
	sqli := &detectSQLi{}
	waf := corazawaf.NewWAF()
	f.Fuzz(func(t *testing.T, tc string) {
		tx := waf.NewTransaction()
		defer tx.Close()
		_ = sqli.Evaluate(tx, tc)
	})
}
