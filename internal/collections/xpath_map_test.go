// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"
	"strings"
	"testing"

	"github.com/antchfx/xmlquery"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func parseTestDoc(t *testing.T, xml string) *xmlquery.Node {
	t.Helper()
	doc, err := xmlquery.Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

const testXML = `<?xml version="1.0"?>
<root>
  <item key="a">alpha</item>
  <item key="b">beta</item>
</root>`

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
		t.Errorf("expected nil, got %v", got)
	}
	if got := m.FindString("//item"); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
	if got := m.FindAll(); got != nil {
		t.Errorf("expected nil, got %v", got)
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
	// Should match results from FindAll whose key is "//@*"
	for _, match := range matches {
		if !re.MatchString(match.Key()) {
			t.Errorf("FindRegex returned match with non-matching key: %q", match.Key())
		}
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
// are safe no-ops that do not panic.
func TestXPathMapMutationNoOps(t *testing.T) {
	doc := parseTestDoc(t, testXML)
	m := NewXPathMap(variables.RequestXML, doc)

	// These should not panic or change behavior
	m.Set("//item", []string{"new"})
	m.Add("//item", "new")
	m.SetIndex("//item", 0, "new")
	m.Remove("//item")

	// Original data should still be accessible
	got := m.Get("//item")
	if len(got) != 2 {
		t.Errorf("mutation methods should be no-ops, but data changed: %v", got)
	}
}
