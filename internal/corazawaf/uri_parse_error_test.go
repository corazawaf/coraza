package corazawaf

import "testing"

// URI_PARSE_ERROR is cleared by the generic reset() on Close, so it is never
// stale across pool reuse. This pins both that and the explicit "0" default,
// so the flag reads like its siblings instead of relying on an empty value
// coercing to zero.
func TestURIParseErrorResetAndDefault(t *testing.T) {
	waf := NewWAF()

	tx1 := waf.NewTransaction()
	tx1.ProcessURI("/bad\x00uri?a=1", "GET", "HTTP/1.1")
	if got := tx1.variables.uriParseError.Get(); got != "1" {
		t.Fatalf("unparseable URI should set the flag, got %q", got)
	}
	if err := tx1.Close(); err != nil {
		t.Fatal(err)
	}

	tx2 := waf.NewTransaction()
	defer tx2.Close()
	tx2.ProcessURI("/perfectly/fine?a=1", "GET", "HTTP/1.1")
	if got := tx2.variables.uriParseError.Get(); got != "0" {
		t.Errorf("a reused transaction with a valid URI must read %q, got %q", "0", got)
	}
}
