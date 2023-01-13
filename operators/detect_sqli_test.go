package operators

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"testing"
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
