package operators

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"testing"
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
