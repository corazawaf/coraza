package experimental

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func makeTransaction(t testing.TB) *Transaction {
	t.Helper()
	tx := corazawaf.NewWAF().NewTransaction()
	etx, ok := tx.(experimental.UnixTimestamp)
	if !ok {
		panic("WAF does not implement WAFWithOptions")
	}
	tx.RequestBodyAccess = true
	ht := []string{
		"POST /testurl.php?id=123&b=456 HTTP/1.1",
		"Host: www.test.com:80",
		"Cookie: test=123",
		"Content-Type: application/x-www-form-urlencoded",
		"X-Test-Header: test456",
		"Content-Length: 13",
		"",
		"testfield=456",
	}
	data := strings.Join(ht, "\r\n")
	_, err := tx.ParseRequestReader(strings.NewReader(data))
	if err != nil {
		panic(err)
	}
	return tx
}

func TestGetUnixTimestamp(t *testing.T) {
	tx := makeTransaction(t)
	stamp := tx.UnixTimestamp()
	t.Logf("stamp: %d", stamp)
	if stamp <= 0 {
		t.Fatalf("no timestamp found")
	}
}
