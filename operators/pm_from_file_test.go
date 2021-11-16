package operators

import (
	"testing"

	"github.com/jptosso/coraza-waf/v2"
)

func TestPmfm(t *testing.T) {
	data := "abc\r\ndef\r\nghi"
	p := &pmFromFile{}
	if err := p.Init(data); err != nil {
		t.Error(err)
	}
	waf := coraza.NewWaf()
	tx := waf.NewTransaction()
	if !p.Evaluate(tx, "def") {
		t.Error("failed to match pmFromFile")
	}
}
