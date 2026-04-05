// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/antchfx/xmlquery"

	"github.com/corazawaf/coraza/v3/types/variables"
)

// testdataDir returns the path to the testdata directory.
// Go test always sets the working directory to the package directory.
func testdataDir(t testing.TB) string {
	t.Helper()
	return "testdata"
}

// parseTestDoc parses an XML string into an xmlquery document.
func parseTestDoc(t testing.TB, xml string) *xmlquery.Node {
	t.Helper()
	doc, err := xmlquery.Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// loadTestdata loads and parses an XML file from the testdata directory.
func loadTestdata(t testing.TB, name string) *xmlquery.Node {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir(t), name))
	if err != nil {
		t.Fatal(err)
	}
	return parseTestDoc(t, string(data))
}

const testXML = `<?xml version="1.0"?>
<root>
  <item key="a">alpha</item>
  <item key="b">beta</item>
</root>`

// ---------------------------------------------------------------------------
// Unit tests — full coverage
// ---------------------------------------------------------------------------

// TestXPathMapGet verifies that Get evaluates an XPath expression and
// returns the string values of matching nodes.
func TestXPathMapGet(t *testing.T) {
	doc := parseTestDoc(t, testXML)
	m := NewXPathMap(variables.RequestXML, doc)

	got := m.Get("//item")
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	if got[0] != "alpha" || got[1] != "beta" {
		t.Errorf("unexpected values: %v", got)
	}
}

// TestXPathMapGetAttributes verifies attribute XPath selection.
func TestXPathMapGetAttributes(t *testing.T) {
	doc := parseTestDoc(t, testXML)
	m := NewXPathMap(variables.RequestXML, doc)

	got := m.Get("//item/@key")
	if len(got) != 2 {
		t.Fatalf("expected 2 attributes, got %d", len(got))
	}
	if got[0] != "a" || got[1] != "b" {
		t.Errorf("unexpected attribute values: %v", got)
	}
}

// TestXPathMapGetNoMatch verifies that a non-matching XPath returns nil.
func TestXPathMapGetNoMatch(t *testing.T) {
	doc := parseTestDoc(t, testXML)
	m := NewXPathMap(variables.RequestXML, doc)

	got := m.Get("//missing")
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

// TestXPathMapGetInvalidXPath verifies that an invalid XPath expression
// returns nil instead of panicking.
func TestXPathMapGetInvalidXPath(t *testing.T) {
	doc := parseTestDoc(t, testXML)
	m := NewXPathMap(variables.RequestXML, doc)

	got := m.Get("[invalid xpath")
	if got != nil {
		t.Errorf("expected nil for invalid xpath, got %v", got)
	}
}

// TestXPathMapNilDoc verifies that a nil document returns nil for all queries.
func TestXPathMapNilDoc(t *testing.T) {
	m := NewXPathMap(variables.RequestXML, nil)

	if got := m.Get("//item"); got != nil {
		t.Errorf("Get: expected nil, got %v", got)
	}
	if got := m.FindString("//item"); got != nil {
		t.Errorf("FindString: expected nil, got %v", got)
	}
	if got := m.FindAll(); got != nil {
		t.Errorf("FindAll: expected nil, got %v", got)
	}
	if got := m.FindRegex(regexp.MustCompile(".")); got != nil {
		t.Errorf("FindRegex: expected nil, got %v", got)
	}
}

// TestXPathMapFindString verifies that FindString returns proper MatchData
// with the correct variable, key, and value fields.
func TestXPathMapFindString(t *testing.T) {
	doc := parseTestDoc(t, testXML)
	m := NewXPathMap(variables.RequestXML, doc)

	matches := m.FindString("//item")
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	if matches[0].Variable().Name() != "REQUEST_XML" {
		t.Errorf("expected variable REQUEST_XML, got %q", matches[0].Variable().Name())
	}
	if matches[0].Key() != "//item" {
		t.Errorf("expected key '//item', got %q", matches[0].Key())
	}
	if matches[0].Value() != "alpha" {
		t.Errorf("expected value 'alpha', got %q", matches[0].Value())
	}
}

// TestXPathMapFindStringNoMatch verifies FindString returns nil for
// a valid XPath that matches nothing.
func TestXPathMapFindStringNoMatch(t *testing.T) {
	doc := parseTestDoc(t, testXML)
	m := NewXPathMap(variables.RequestXML, doc)

	matches := m.FindString("//nonexistent")
	if matches != nil {
		t.Errorf("expected nil, got %d matches", len(matches))
	}
}

// TestXPathMapFindStringEmpty verifies that FindString with an empty key
// delegates to FindAll.
func TestXPathMapFindStringEmpty(t *testing.T) {
	doc := parseTestDoc(t, testXML)
	m := NewXPathMap(variables.RequestXML, doc)

	all := m.FindString("")
	if len(all) == 0 {
		t.Error("expected results from FindString(\"\"), got none")
	}
}

// TestXPathMapFindRegex verifies that FindRegex filters results by key match.
func TestXPathMapFindRegex(t *testing.T) {
	doc := parseTestDoc(t, testXML)
	m := NewXPathMap(variables.RequestXML, doc)

	re := regexp.MustCompile(`//@\*`)
	matches := m.FindRegex(re)
	for _, match := range matches {
		if !re.MatchString(match.Key()) {
			t.Errorf("FindRegex returned match with non-matching key: %q", match.Key())
		}
	}
}

// TestXPathMapFindRegexNoMatch verifies FindRegex returns nil when
// regex matches no keys from FindAll.
func TestXPathMapFindRegexNoMatch(t *testing.T) {
	doc := parseTestDoc(t, testXML)
	m := NewXPathMap(variables.RequestXML, doc)

	re := regexp.MustCompile(`^WILL_NEVER_MATCH$`)
	matches := m.FindRegex(re)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

// TestXPathMapFindAll verifies FindAll returns both attributes and text content.
func TestXPathMapFindAll(t *testing.T) {
	doc := parseTestDoc(t, testXML)
	m := NewXPathMap(variables.RequestXML, doc)

	all := m.FindAll()
	if len(all) == 0 {
		t.Fatal("expected results from FindAll, got none")
	}

	// Should have attribute results (key="//@*") and text results (key="//*[text()]")
	var attrCount, textCount int
	for _, md := range all {
		switch md.Key() {
		case "//@*":
			attrCount++
		case "//*[text()]":
			textCount++
		}
	}
	if attrCount == 0 {
		t.Error("expected attribute results in FindAll")
	}
	if textCount == 0 {
		t.Error("expected text results in FindAll")
	}
}

// TestXPathMapName verifies the collection name matches the variable.
func TestXPathMapName(t *testing.T) {
	m := NewXPathMap(variables.RequestXML, nil)
	if m.Name() != "REQUEST_XML" {
		t.Errorf("expected name 'REQUEST_XML', got %q", m.Name())
	}
}

// TestXPathMapReset verifies that Reset clears the document reference,
// causing subsequent queries to return nil.
func TestXPathMapReset(t *testing.T) {
	doc := parseTestDoc(t, testXML)
	m := NewXPathMap(variables.RequestXML, doc)

	if got := m.Get("//item"); len(got) == 0 {
		t.Fatal("expected results before reset")
	}

	m.Reset()

	if got := m.Get("//item"); got != nil {
		t.Errorf("expected nil after reset, got %v", got)
	}
}

// TestXPathMapMutationNoOps verifies that Set, Add, SetIndex, and Remove
// are safe no-ops that do not panic or alter query results.
func TestXPathMapMutationNoOps(t *testing.T) {
	doc := parseTestDoc(t, testXML)
	m := NewXPathMap(variables.RequestXML, doc)

	m.Set("//item", []string{"new"})
	m.Add("//item", "new")
	m.SetIndex("//item", 0, "new")
	m.Remove("//item")

	got := m.Get("//item")
	if len(got) != 2 {
		t.Errorf("mutation methods should be no-ops, but data changed: %v", got)
	}
}

// TestXPathMapFormat verifies that Format writes the expected representation.
func TestXPathMapFormat(t *testing.T) {
	m := NewXPathMap(variables.RequestXML, nil)
	var b strings.Builder
	m.Format(&b)
	out := b.String()
	if !strings.Contains(out, "REQUEST_XML") {
		t.Errorf("Format output missing variable name: %q", out)
	}
	if !strings.Contains(out, "xpath-backed") {
		t.Errorf("Format output missing type indicator: %q", out)
	}
}

// ---------------------------------------------------------------------------
// Tests with diverse XML structures from testdata
// ---------------------------------------------------------------------------

// TestXPathMapSOAPNamespaces verifies XPath queries with XML namespaces.
func TestXPathMapSOAPNamespaces(t *testing.T) {
	doc := loadTestdata(t, "small_soap.xml")
	m := NewXPathMap(variables.RequestXML, doc)

	got := m.Get("//*[local-name()='StockName']")
	if len(got) != 1 || got[0] != "GOOG" {
		t.Errorf("expected [GOOG], got %v", got)
	}

	got = m.Get("//*[local-name()='Token']")
	if len(got) != 1 || got[0] != "secret-token-123" {
		t.Errorf("expected [secret-token-123], got %v", got)
	}
}

// TestXPathMapCDATA verifies that CDATA content is accessible via XPath.
func TestXPathMapCDATA(t *testing.T) {
	doc := loadTestdata(t, "small_cdata.xml")
	m := NewXPathMap(variables.RequestXML, doc)

	got := m.Get("//body")
	if len(got) != 2 {
		t.Fatalf("expected 2 body elements, got %d: %v", len(got), got)
	}
	// CDATA content should be returned as-is (without the CDATA markers)
	if !strings.Contains(got[0], "<b>world</b>") {
		t.Errorf("expected CDATA content with HTML tags, got %q", got[0])
	}

	// Attribute queries on CDATA doc
	got = m.Get("//message/@priority")
	if len(got) != 2 || got[0] != "high" || got[1] != "low" {
		t.Errorf("expected [high, low], got %v", got)
	}
}

// TestXPathMapXMLRPC verifies parsing of XML-RPC structures.
func TestXPathMapXMLRPC(t *testing.T) {
	doc := loadTestdata(t, "small_xmlrpc.xml")
	m := NewXPathMap(variables.RequestXML, doc)

	got := m.Get("//methodName")
	if len(got) != 1 || got[0] != "wp.getUsersBlogs" {
		t.Errorf("expected [wp.getUsersBlogs], got %v", got)
	}

	got = m.Get("//params/param/value/string")
	if len(got) != 2 || got[0] != "admin" || got[1] != "password123" {
		t.Errorf("expected [admin, password123], got %v", got)
	}

	got = m.Get("//params/param/value/i4")
	if len(got) != 1 || got[0] != "42" {
		t.Errorf("expected [42], got %v", got)
	}
}

// TestXPathMapMediumMixed verifies queries against a medium-sized document
// with namespaces, CDATA, attributes, and nested structures.
func TestXPathMapMediumMixed(t *testing.T) {
	doc := loadTestdata(t, "medium_mixed.xml")
	m := NewXPathMap(variables.RequestXML, doc)

	// Count all books
	got := m.Get("//*[local-name()='book']")
	if len(got) != 50 {
		t.Errorf("expected 50 books, got %d", len(got))
	}

	// Query by attribute predicate
	got = m.Get("//*[local-name()='book'][@category='fiction']")
	if len(got) == 0 {
		t.Error("expected fiction books, got none")
	}

	// Query for specific attribute values
	got = m.Get("//*[local-name()='book']/@format")
	if len(got) != 50 {
		t.Errorf("expected 50 format attributes, got %d", len(got))
	}

	// Nested review elements
	got = m.Get("//*[local-name()='reviewer']")
	if len(got) == 0 {
		t.Error("expected reviewers, got none")
	}

	// Metadata elements (every 7th book)
	got = m.Get("//*[local-name()='metadata']/@key")
	if len(got) == 0 {
		t.Error("expected metadata attributes, got none")
	}
}

// TestXPathMapDeepNesting verifies XPath on deeply nested documents.
func TestXPathMapDeepNesting(t *testing.T) {
	doc := loadTestdata(t, "medium_deep.xml")
	m := NewXPathMap(variables.RequestXML, doc)

	// Query deepest level
	got := m.Get("//*[local-name()='level'][@depth='30']/*[local-name()='data']")
	if len(got) != 1 || got[0] != "Value at depth 30" {
		t.Errorf("expected [Value at depth 30], got %v", got)
	}

	// All data elements
	got = m.Get("//*[local-name()='data']")
	if len(got) != 30 {
		t.Errorf("expected 30 data elements, got %d", len(got))
	}

	// Siblings (every 5th level)
	got = m.Get("//*[local-name()='sibling']")
	if len(got) != 12 { // 6 levels * 2 siblings
		t.Errorf("expected 12 siblings, got %d", len(got))
	}
}

// TestXPathMapLargeDocQueries verifies various query patterns against a
// large document (500 employee records with multiple namespaces).
func TestXPathMapLargeDocQueries(t *testing.T) {
	doc := loadTestdata(t, "large_catalog.xml")
	m := NewXPathMap(variables.RequestXML, doc)

	// Count all employees
	got := m.Get("//*[local-name()='employee']")
	if len(got) != 500 {
		t.Errorf("expected 500 employees, got %d", len(got))
	}

	// Query specific namespace prefix using local-name()
	got = m.Get("//*[local-name()='salary']")
	if len(got) != 500 {
		t.Errorf("expected 500 salaries, got %d", len(got))
	}

	// Predicate on attribute
	got = m.Get("//*[local-name()='employee'][@department='Engineering']")
	if len(got) == 0 {
		t.Error("expected Engineering employees, got none")
	}

	// CDATA notes (every 10th employee)
	got = m.Get("//*[local-name()='notes']")
	if len(got) != 50 {
		t.Errorf("expected 50 notes, got %d", len(got))
	}

	// Access log entries (every 5th employee, 5 entries each)
	got = m.Get("//*[local-name()='entry']/@action")
	if len(got) != 500 { // 100 employees * 5 entries
		t.Errorf("expected 500 access log actions, got %d", len(got))
	}
}

// TestXPathMapWhitespaceOnlyNodes verifies that nodes with only whitespace
// text content are excluded from results.
func TestXPathMapWhitespaceOnlyNodes(t *testing.T) {
	xml := `<?xml version="1.0"?>
<root>
  <empty>   </empty>
  <content>real value</content>
  <tabs>		</tabs>
</root>`
	doc := parseTestDoc(t, xml)
	m := NewXPathMap(variables.RequestXML, doc)

	got := m.Get("//*[local-name()='empty']")
	if len(got) != 0 {
		t.Errorf("expected whitespace-only node to be excluded, got %v", got)
	}
	got = m.Get("//*[local-name()='content']")
	if len(got) != 1 || got[0] != "real value" {
		t.Errorf("expected [real value], got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks — small, medium, large documents with various XPath patterns
// ---------------------------------------------------------------------------

// benchmarkXPath is a helper that loads a document once and benchmarks
// repeated XPath evaluation.
func benchmarkXPath(b *testing.B, docName, xpath string) {
	b.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir(b), docName))
	if err != nil {
		b.Fatal(err)
	}
	doc, err := xmlquery.Parse(strings.NewReader(string(data)))
	if err != nil {
		b.Fatal(err)
	}
	m := NewXPathMap(variables.RequestXML, doc)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		m.Get(xpath)
	}
}

// benchmarkParse measures the cost of parsing the XML document itself.
func benchmarkParse(b *testing.B, docName string) {
	b.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir(b), docName))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := xmlquery.Parse(strings.NewReader(string(data)))
		if err != nil {
			b.Fatal(err)
		}
	}
}

// --- Small document benchmarks ---

func BenchmarkSmall_Parse(b *testing.B) {
	benchmarkParse(b, "small_simple.xml")
}

func BenchmarkSmall_GetElement(b *testing.B) {
	benchmarkXPath(b, "small_simple.xml", "//item")
}

func BenchmarkSmall_GetAttribute(b *testing.B) {
	benchmarkXPath(b, "small_simple.xml", "//item/@key")
}

func BenchmarkSmall_GetAllAttributes(b *testing.B) {
	benchmarkXPath(b, "small_simple.xml", "//@*")
}

func BenchmarkSmall_FindAll(b *testing.B) {
	data, _ := os.ReadFile(filepath.Join(testdataDir(b), "small_simple.xml"))
	doc, _ := xmlquery.Parse(strings.NewReader(string(data)))
	m := NewXPathMap(variables.RequestXML, doc)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		m.FindAll()
	}
}

// --- Small SOAP (namespace-heavy) ---

func BenchmarkSmallSOAP_Parse(b *testing.B) {
	benchmarkParse(b, "small_soap.xml")
}

func BenchmarkSmallSOAP_LocalName(b *testing.B) {
	benchmarkXPath(b, "small_soap.xml", "//*[local-name()='StockName']")
}

// --- Small CDATA ---

func BenchmarkSmallCDATA_Parse(b *testing.B) {
	benchmarkParse(b, "small_cdata.xml")
}

func BenchmarkSmallCDATA_GetBody(b *testing.B) {
	benchmarkXPath(b, "small_cdata.xml", "//body")
}

// --- Medium document benchmarks (50 books, ~22KB) ---

func BenchmarkMedium_Parse(b *testing.B) {
	benchmarkParse(b, "medium_mixed.xml")
}

func BenchmarkMedium_GetAllBooks(b *testing.B) {
	benchmarkXPath(b, "medium_mixed.xml", "//*[local-name()='book']")
}

func BenchmarkMedium_GetByAttribute(b *testing.B) {
	benchmarkXPath(b, "medium_mixed.xml", "//*[local-name()='book'][@category='fiction']")
}

func BenchmarkMedium_GetNestedReviews(b *testing.B) {
	benchmarkXPath(b, "medium_mixed.xml", "//*[local-name()='review']/@rating")
}

func BenchmarkMedium_GetAllAttributes(b *testing.B) {
	benchmarkXPath(b, "medium_mixed.xml", "//@*")
}

func BenchmarkMedium_FindAll(b *testing.B) {
	data, _ := os.ReadFile(filepath.Join(testdataDir(b), "medium_mixed.xml"))
	doc, _ := xmlquery.Parse(strings.NewReader(string(data)))
	m := NewXPathMap(variables.RequestXML, doc)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		m.FindAll()
	}
}

// --- Medium deep document benchmarks (30 levels, ~9KB) ---

func BenchmarkMediumDeep_Parse(b *testing.B) {
	benchmarkParse(b, "medium_deep.xml")
}

func BenchmarkMediumDeep_QueryDeepest(b *testing.B) {
	benchmarkXPath(b, "medium_deep.xml", "//*[local-name()='level'][@depth='30']/*[local-name()='data']")
}

func BenchmarkMediumDeep_QueryAllData(b *testing.B) {
	benchmarkXPath(b, "medium_deep.xml", "//*[local-name()='data']")
}

// --- Large document benchmarks (500 employees, ~298KB) ---

func BenchmarkLarge_Parse(b *testing.B) {
	benchmarkParse(b, "large_catalog.xml")
}

func BenchmarkLarge_GetAllEmployees(b *testing.B) {
	benchmarkXPath(b, "large_catalog.xml", "//*[local-name()='employee']")
}

func BenchmarkLarge_GetByDepartment(b *testing.B) {
	benchmarkXPath(b, "large_catalog.xml", "//*[local-name()='employee'][@department='Engineering']")
}

func BenchmarkLarge_GetSalaries(b *testing.B) {
	benchmarkXPath(b, "large_catalog.xml", "//*[local-name()='salary']")
}

func BenchmarkLarge_GetAccessLogActions(b *testing.B) {
	benchmarkXPath(b, "large_catalog.xml", "//*[local-name()='entry']/@action")
}

func BenchmarkLarge_GetCDATANotes(b *testing.B) {
	benchmarkXPath(b, "large_catalog.xml", "//*[local-name()='notes']")
}

func BenchmarkLarge_GetAllAttributes(b *testing.B) {
	benchmarkXPath(b, "large_catalog.xml", "//@*")
}

func BenchmarkLarge_FindAll(b *testing.B) {
	data, _ := os.ReadFile(filepath.Join(testdataDir(b), "large_catalog.xml"))
	doc, _ := xmlquery.Parse(strings.NewReader(string(data)))
	m := NewXPathMap(variables.RequestXML, doc)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		m.FindAll()
	}
}

// --- FindString benchmarks (measures MatchData allocation) ---

func BenchmarkLarge_FindString_Employees(b *testing.B) {
	data, _ := os.ReadFile(filepath.Join(testdataDir(b), "large_catalog.xml"))
	doc, _ := xmlquery.Parse(strings.NewReader(string(data)))
	m := NewXPathMap(variables.RequestXML, doc)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		m.FindString("//*[local-name()='employee']")
	}
}

func BenchmarkLarge_FindRegex(b *testing.B) {
	data, _ := os.ReadFile(filepath.Join(testdataDir(b), "large_catalog.xml"))
	doc, _ := xmlquery.Parse(strings.NewReader(string(data)))
	m := NewXPathMap(variables.RequestXML, doc)
	re := regexp.MustCompile(`text`)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		m.FindRegex(re)
	}
}
