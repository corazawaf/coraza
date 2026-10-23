// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"bytes"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
	corazaStrings "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/internal/variables"
)

type testTransactionVariables struct {
	plugintypes.TransactionVariables
	requestXML            *collections.Map
	responseXML           *collections.Map
	argumentsLimitReached *collections.Single
}

func (tv *testTransactionVariables) RequestXML() collection.Map {
	return tv.requestXML
}

func (tv *testTransactionVariables) ResponseXML() collection.Map {
	return tv.responseXML
}

func (tv *testTransactionVariables) ArgumentsLimitReached() collection.Single {
	return tv.argumentsLimitReached
}

func newTestTransactionVariables() *testTransactionVariables {
	return &testTransactionVariables{
		requestXML:            collections.NewMap(variables.RequestXML),
		responseXML:           collections.NewMap(variables.ResponseXML),
		argumentsLimitReached: collections.NewSingle(variables.ArgumentsLimitReached),
	}
}

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
	attrs, contents, _, err := readXML(bytes.NewReader([]byte(xmldoc)), 0)
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
		if !corazaStrings.InSlice(attr, attrs) {
			t.Errorf("Expected attribute %s, got %v", attr, attrs)
		}
	}
	for _, content := range econtent {
		if !corazaStrings.InSlice(content, contents) {
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
	_, contents, _, err := readXML(bytes.NewReader([]byte(xmldoc)), 0)
	if err != nil {
		t.Error(err)
	}
	for _, content := range []string{"Tove", "Jani", "Reminder", "Don't forget me this weekend!"} {
		if !corazaStrings.InSlice(content, contents) {
			t.Errorf("Expected content %s, got %v", content, contents)
		}
	}
	if len(contents) != 4 {
		t.Errorf("Expected 4 contents, got %d", len(contents))
	}
}

func TestXMLUnexpectedEOF(t *testing.T) {
	testCases := []struct {
		Name  string
		Input string
		Want  []string
	}{
		{
			Name: "inTheMiddleOfText",
			Input: `<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading>
			<body>Don't forget`,
			Want: []string{"Tove", "Jani", "Reminder", "Don't forget"},
		},
		{
			Name: "inTheMiddleOfStartElement",
			Input: `<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading>
			<bod`,
			Want: []string{"Tove", "Jani", "Reminder"},
		},
		{
			Name: "inTheMiddleOfEndElement",
			Input: `<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading`,
			Want: []string{"Tove", "Jani", "Reminder"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			xmldoc := tc.Input
			_, contents, _, err := readXML(bytes.NewReader([]byte(xmldoc)), 0)
			if err != nil {
				t.Error(err)
			}
			if got, want := len(contents), len(tc.Want); got != want {
				t.Errorf("contents count mismatch, got=%d, want=%d", got, want)
			}
			for i := range min(len(contents), len(tc.Want)) {
				if got, want := contents[i], tc.Want[i]; got != want {
					t.Errorf("Expected content got=%s, want=%s", got, want)
				}
			}
		})
	}
}

func TestXMLProcessResponseAndArgumentLimit(t *testing.T) {
	bp := &xmlBodyProcessor{}
	xmldoc := `<response status="ok" code="200" extra="val"><data>SecretPayload</data><more>Text</more></response>`

	// Without limit
	v := newTestTransactionVariables()
	err := bp.ProcessResponse(strings.NewReader(xmldoc), v, plugintypes.BodyProcessorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if v.ArgumentsLimitReached().Get() == "1" {
		t.Error("expected ArgumentsLimitReached not to be set")
	}
	if len(v.ResponseXML().Get("//@*")) != 3 {
		t.Errorf("expected 3 attributes, got %d", len(v.ResponseXML().Get("//@*")))
	}
	if len(v.ResponseXML().Get("/*")) != 2 {
		t.Errorf("expected 2 contents, got %d", len(v.ResponseXML().Get("/*")))
	}

	// With ArgumentLimit = 2 (caps total collected attrs + contents to 2)
	vLimited := newTestTransactionVariables()
	err = bp.ProcessResponse(strings.NewReader(xmldoc), vLimited, plugintypes.BodyProcessorOptions{
		ArgumentLimit: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if vLimited.ArgumentsLimitReached().Get() != "1" {
		t.Error("expected ArgumentsLimitReached to be set to 1")
	}
	total := len(vLimited.ResponseXML().Get("//@*")) + len(vLimited.ResponseXML().Get("/*"))
	if total != 2 {
		t.Errorf("expected 2 total XML items with limit=2, got %d", total)
	}
}
