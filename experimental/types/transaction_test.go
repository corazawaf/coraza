package types

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func makeTransaction(t testing.TB) Transaction {
	t.Helper()
	waf, _ := coraza.NewWAF(coraza.NewWAFConfig().WithRequestBodyAccess())
	tx := waf.NewTransaction()
	tx.ProcessConnection("", 80, "", 443)
	return tx.(Transaction)
}

func TestGetUnixTimestamp(t *testing.T) {
	tx := makeTransaction(t)
	stamp := tx.UnixTimestamp()
	t.Logf("stamp: %d", stamp)
	if stamp <= 0 {
		t.Fatalf("no timestamp found")
	}
}
