// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v4/internal/corazawaf"
)

var xssTests = []string{
	"",
	"this is not an XSS",
	"<a href=\"javascript:alert(1)\">)",
	"href=&#",
	"href=&#X",
}

func FuzzXSS(f *testing.F) {
	for _, tc := range xssTests {
		f.Add(tc)
	}
	xss := &detectXSS{}
	waf := corazawaf.NewWAF()
	f.Fuzz(func(t *testing.T, tc string) {
		tx := waf.NewTransaction()
		defer tx.Close()
		_ = xss.Evaluate(tx, tc)
	})
}
