// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"bytes"
	"errors"
	stdstrings "strings"
	"testing"

	corazastrings "github.com/corazawaf/coraza/v3/internal/strings"
)

func TestXMLAttribures(t *testing.T) {
	xmldoc := `<?xml version="1.0" encoding="UTF-8"?>
<bookstore>
<book>
  <title lang="en">Harry <bold>Potter</bold> Biography</title>
  <price secret="value">29.99</price>
</book>

<book>
  <title lang="en">Learning XML</title>
  <price>39.95</price>
</book>

</bookstore>`
	attrs, contents, err := readXML(bytes.NewReader([]byte(xmldoc)))
	if err != nil {
		t.Error(err)
	}
	if len(attrs) != 3 {
		t.Errorf("Expected 3 attributes, got %d", len(attrs))
	}
	if len(contents) != 6 {
		t.Errorf("Expected 6 contents, got %d", len(contents))
	}
	eattrs := []string{"en", "value"}
	econtent := []string{"Harry", "Potter", "Biography", "29.99", "Learning XML", "39.95"}
	for _, attr := range eattrs {
		if !corazastrings.InSlice(attr, attrs) {
			t.Errorf("Expected attribute %s, got %v", attr, attrs)
		}
	}
	for _, content := range econtent {
		if !corazastrings.InSlice(content, contents) {
			t.Errorf("Expected content %s, got %v", content, contents)
		}
	}
}

func TestXMLPayloadFlexibility(t *testing.T) {
	xmldoc := `<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading>
			<body>Don't forget me this weekend!
		</note>`
	_, contents, err := readXML(bytes.NewReader([]byte(xmldoc)))
	if err != nil {
		t.Error(err)
	}
	for _, content := range []string{"Tove", "Jani", "Reminder", "Don't forget me this weekend!"} {
		if !corazastrings.InSlice(content, contents) {
			t.Errorf("Expected content %s, got %v", content, contents)
		}
	}
	if len(contents) != 4 {
		t.Errorf("Expected 4 contents, got %d", len(contents))
	}
}

func TestXMLWithInvalidInput(t *testing.T) {
	// Test with malformed XML
	malformedXML := `<root><unclosed>`
	_, _, err := readXML(stdstrings.NewReader(malformedXML))
	if err == nil {
		t.Error("Expected error with malformed XML, got nil")
	}
}

func TestXMLWithReadError(t *testing.T) {
	// Test with a reader that returns an error
	r := &errorReader{errors.New("read error")}
	_, _, err := readXML(r)
	if err == nil {
		t.Error("Expected error from failing reader, got nil")
	}
}

func TestXMLWithEmptyDocument(t *testing.T) {
	// Test with empty document - the parser is forgiving and doesn't error
	emptyXML := ""
	attrs, contents, err := readXML(stdstrings.NewReader(emptyXML))
	if err != nil {
		t.Error(err)
	}
	if len(attrs) != 0 {
		t.Errorf("Expected 0 attributes for empty doc, got %d", len(attrs))
	}
	if len(contents) != 0 {
		t.Errorf("Expected 0 contents for empty doc, got %d", len(contents))
	}
}

func TestXMLWithNestedElements(t *testing.T) {
	// Test deeply nested elements
	nestedXML := `
	<root>
		<level1>
			<level2>
				<level3 attr="value">
					<level4>Deep content</level4>
				</level3>
			</level2>
		</level1>
	</root>
	`
	attrs, contents, err := readXML(stdstrings.NewReader(nestedXML))
	if err != nil {
		t.Error(err)
	}

	if len(attrs) != 1 {
		t.Errorf("Expected 1 attribute, got %d", len(attrs))
	}
	if !corazastrings.InSlice("value", attrs) {
		t.Errorf("Expected attribute 'value', not found in %v", attrs)
	}

	if !corazastrings.InSlice("Deep content", contents) {
		t.Errorf("Expected content 'Deep content', not found in %v", contents)
	}
}

func TestXMLWithSpecialEntities(t *testing.T) {
	// Test XML with special entities
	entityXML := `
	<root>
		<element>Text with &lt;brackets&gt; and &amp; ampersand</element>
		<special>A &quot;quoted&quot; text with &#39;apostrophes&#39;</special>
	</root>
	`
	_, contents, err := readXML(stdstrings.NewReader(entityXML))
	if err != nil {
		t.Error(err)
	}

	expectedContents := []string{
		"Text with <brackets> and & ampersand",
		"A \"quoted\" text with 'apostrophes'",
	}

	for _, expected := range expectedContents {
		found := false
		for _, content := range contents {
			if content == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected content %q not found in %v", expected, contents)
		}
	}
}

// errorReader implements io.Reader but always returns an error
type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}
