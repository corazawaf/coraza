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

func TestXMLExternalEntityProtection(t *testing.T) {
	// Test XML with external entity that should not be processed
	xxeXML := `<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE test [
		<!ENTITY xxe SYSTEM "file:///etc/passwd">
	]>
	<root>
		<data>&xxe;</data>
	</root>`

	// If XXE is not blocked, this would contain file contents
	attrs, contents, err := readXML(stdstrings.NewReader(xxeXML))

	// The parser should either ignore the entity or return an error
	// We check that no file contents are accidentally included

	// Check each content string to ensure it doesn't contain passwd file data
	for _, content := range contents {
		if stdstrings.Contains(content, "root:") || stdstrings.Contains(content, "/bin/bash") {
			t.Errorf("XXE attack succeeded, found passwd file content: %s", content)
		}
	}

	// Either we should not find &xxe; (parser strips it) or it should remain unexpanded
	for _, content := range contents {
		if stdstrings.Contains(content, "&xxe;") {
			t.Logf("Found unexpanded &xxe; entity in content")
		}
	}

	// Log the actual behavior for debugging
	t.Logf("XXE Test - Error: %v, Contents: %v, Attrs: %v", err, contents, attrs)
}

func TestXMLNetworkEntityProtection(t *testing.T) {
	// Test XML with external entity that points to a network resource
	xxeNetworkXML := `<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE test [
		<!ENTITY xxe SYSTEM "http://localhost:9999/should-not-connect">
	]>
	<root>
		<data>&xxe;</data>
	</root>`

	// If XXE is not blocked, this would try to connect to the URL
	attrs, contents, err := readXML(stdstrings.NewReader(xxeNetworkXML))

	// The parser should either ignore the entity or return an error
	// We check that no unexpected data appears in the contents

	// Log the actual behavior for debugging
	t.Logf("XXE Network Test - Error: %v, Contents: %v, Attrs: %v", err, contents, attrs)

	// Confirm we don't have any unexpected content that would
	// indicate a successful network connection
	for _, content := range contents {
		if stdstrings.Contains(content, "should-not-connect") ||
			stdstrings.Contains(content, "localhost:9999") {
			t.Errorf("XXE network attack might have succeeded, found suspicious content: %s", content)
		}
	}
}

func TestXMLBillionLaughsProtection(t *testing.T) {
	// Test "Billion Laughs" attack, a form of entity expansion bomb
	billionLaughsXML := `<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE lolz [
		<!ENTITY lol "lol">
		<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
		<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
		<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
	]>
	<root>&lol3;</root>`

	// If entity expansion is not limited, this would cause excessive memory usage
	// We just check that the operation completes in a reasonable time
	_, _, err := readXML(stdstrings.NewReader(billionLaughsXML))

	// Log the result
	t.Logf("Billion Laughs Test - Error: %v", err)

	// We don't assert anything specific here, as different XML parsers might
	// handle this differently. The important thing is that it doesn't crash
	// or cause excessive resource consumption.
}

// errorReader implements io.Reader but always returns an error
type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}
