// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugins_test

import (
	"bytes"
	"testing"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	internalcollections "github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types/variables"

	// Blank import to trigger init() registration of the xmlquery body processor.
	_ "github.com/corazawaf/coraza/v3/experimental/plugins"
)

const bookstoreXML = `<?xml version="1.0" encoding="UTF-8"?>
<bookstore>
<book>
  <title lang="en">Harry Potter</title>
  <price secret="value">29.99</price>
</book>
<book>
  <title lang="es">Learning XML</title>
  <price>39.95</price>
</book>
</bookstore>`

const soapXML = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetPrice xmlns:m="https://www.example.org/stock">
      <m:StockName>GOOG</m:StockName>
    </m:GetPrice>
  </soap:Body>
</soap:Envelope>`

const xmlRPC = `<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>password123</string></value></param>
  </params>
</methodCall>`

func xmlQueryProcessor(t *testing.T) plugintypes.BodyProcessor {
	t.Helper()
	bp, err := bodyprocessors.GetBodyProcessor("xmlquery")
	if err != nil {
		t.Fatal(err)
	}
	return bp
}

// TestXMLQueryBodyProcessorXPath verifies that the xmlquery body processor
// installs a lazy XPath collection that can evaluate arbitrary XPath
// expressions against the parsed document.
func TestXMLQueryBodyProcessorXPath(t *testing.T) {
	v := corazawaf.NewTransactionVariables()
	bp := xmlQueryProcessor(t)
	err := bp.ProcessRequest(
		bytes.NewReader([]byte(bookstoreXML)),
		v,
		plugintypes.BodyProcessorOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		xpath  string
		expect []string
	}{
		{
			name:   "all titles",
			xpath:  "//title",
			expect: []string{"Harry Potter", "Learning XML"},
		},
		{
			name:   "all prices",
			xpath:  "//price",
			expect: []string{"29.99", "39.95"},
		},
		{
			name:   "first book title",
			xpath:  "//book[1]/title",
			expect: []string{"Harry Potter"},
		},
		{
			name:   "attribute selection",
			xpath:  "//title/@lang",
			expect: []string{"en", "es"},
		},
		{
			name:   "backward compat //@*",
			xpath:  "//@*",
			expect: []string{"en", "value", "es"},
		},
		{
			name:   "text nodes via //text()",
			xpath:  "//text()",
			expect: []string{"Harry Potter", "29.99", "Learning XML", "39.95"},
		},
		{
			name:   "no match",
			xpath:  "//nonexistent",
			expect: nil,
		},
	}

	col := v.RequestXML()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := col.Get(tt.xpath)
			if tt.expect == nil {
				if len(got) != 0 {
					t.Errorf("expected no results, got %v", got)
				}
				return
			}
			if len(got) != len(tt.expect) {
				t.Fatalf("expected %d results, got %d: %v", len(tt.expect), len(got), got)
			}
			for i := range tt.expect {
				if got[i] != tt.expect[i] {
					t.Errorf("result[%d]: expected %q, got %q", i, tt.expect[i], got[i])
				}
			}
		})
	}
}

// TestXMLQueryBodyProcessorSOAP verifies namespace-aware XPath evaluation
// on a SOAP envelope.
func TestXMLQueryBodyProcessorSOAP(t *testing.T) {
	v := corazawaf.NewTransactionVariables()
	bp := xmlQueryProcessor(t)
	err := bp.ProcessRequest(
		bytes.NewReader([]byte(soapXML)),
		v,
		plugintypes.BodyProcessorOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	col := v.RequestXML()

	// Namespace-aware query using local-name()
	got := col.Get("//*[local-name()='StockName']")
	if len(got) != 1 || got[0] != "GOOG" {
		t.Errorf("expected [GOOG], got %v", got)
	}
}

// TestXMLQueryBodyProcessorXMLRPC verifies parsing of WordPress XML-RPC
// requests, the original scenario from issue #1441.
func TestXMLQueryBodyProcessorXMLRPC(t *testing.T) {
	v := corazawaf.NewTransactionVariables()
	bp := xmlQueryProcessor(t)
	err := bp.ProcessRequest(
		bytes.NewReader([]byte(xmlRPC)),
		v,
		plugintypes.BodyProcessorOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	col := v.RequestXML()

	got := col.Get("//methodName")
	if len(got) != 1 || got[0] != "wp.getUsersBlogs" {
		t.Errorf("expected [wp.getUsersBlogs], got %v", got)
	}

	got = col.Get("//params/param/value/string")
	if len(got) != 2 {
		t.Fatalf("expected 2 params, got %d: %v", len(got), got)
	}
	if got[0] != "admin" || got[1] != "password123" {
		t.Errorf("expected [admin, password123], got %v", got)
	}
}

// TestXMLQueryBodyProcessorFindString verifies that FindString returns
// proper MatchData for rule evaluation.
func TestXMLQueryBodyProcessorFindString(t *testing.T) {
	v := corazawaf.NewTransactionVariables()
	bp := xmlQueryProcessor(t)
	err := bp.ProcessRequest(
		bytes.NewReader([]byte(bookstoreXML)),
		v,
		plugintypes.BodyProcessorOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	col := v.RequestXML()
	matches := col.FindString("//title")
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	if matches[0].Value() != "Harry Potter" {
		t.Errorf("expected 'Harry Potter', got %q", matches[0].Value())
	}
	if matches[0].Key() != "//title" {
		t.Errorf("expected key '//title', got %q", matches[0].Key())
	}
}

// TestXMLQueryBodyProcessorFallback verifies that the body processor falls
// back to populating the standard map keys when SetRequestXML is not available.
func TestXMLQueryBodyProcessorFallback(t *testing.T) {
	xmlMap := internalcollections.NewMap(variables.RequestXML)

	// Use a TransactionVariables mock that does not implement xmlSettableVariables.
	vars := &fallbackTestVars{requestXML: xmlMap}

	bp := xmlQueryProcessor(t)
	err := bp.ProcessRequest(
		bytes.NewReader([]byte(bookstoreXML)),
		vars,
		plugintypes.BodyProcessorOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	attrs := xmlMap.Get("//@*")
	if len(attrs) != 3 {
		t.Errorf("expected 3 attributes, got %d: %v", len(attrs), attrs)
	}

	contents := xmlMap.Get("/*")
	if len(contents) == 0 {
		t.Error("expected content in /*, got none")
	}
}

// TestXMLQueryBodyProcessorInvalidXML verifies that malformed XML returns
// an error instead of silently succeeding.
func TestXMLQueryBodyProcessorInvalidXML(t *testing.T) {
	v := corazawaf.NewTransactionVariables()
	bp := xmlQueryProcessor(t)
	err := bp.ProcessRequest(
		bytes.NewReader([]byte("<unclosed><tag>")),
		v,
		plugintypes.BodyProcessorOptions{},
	)
	if err == nil {
		t.Error("expected error for malformed XML, got nil")
	}
}

// fallbackTestVars is a minimal TransactionVariables implementation that does
// NOT implement xmlSettableVariables, forcing the body processor to use the
// fallback path of populating the existing collection.Map directly.
type fallbackTestVars struct {
	plugintypes.TransactionVariables
	requestXML collection.Map
}

// RequestXML returns the test collection without supporting SetRequestXML.
func (v *fallbackTestVars) RequestXML() collection.Map {
	return v.requestXML
}
