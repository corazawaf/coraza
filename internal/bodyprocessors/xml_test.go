// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"bytes"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/strings"
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
		if !strings.InSlice(attr, attrs) {
			t.Errorf("Expected attribute %s, got %v", attr, attrs)
		}
	}
	for _, content := range econtent {
		if !strings.InSlice(content, contents) {
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
		if !strings.InSlice(content, contents) {
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
			_, contents, err := readXML(bytes.NewReader([]byte(xmldoc)))
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

func TestXMLHTMLVoidElementNames(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		wantAttrs []string
		want      []string
	}{
		{
			name:  "xmlrpcParamWithEndTag",
			input: `<methodCall><methodName>m</methodName><params><param><value><int>0</int></value></param></params></methodCall>`,
			want:  []string{"m", "0"},
		},
		{
			name:      "atomLinkAndMetaWithEndTags",
			input:     `<feed><link href="a"></link><link href="b"/><meta>m</meta><source>s</source></feed>`,
			wantAttrs: []string{"a", "b"},
			want:      []string{"m", "s"},
		},
		{
			name:      "unclosedVoidElementIsStillTolerated",
			input:     `<root><br><img src="a"><x>text</x></root>`,
			wantAttrs: []string{"a"},
			want:      []string{"text"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attrs, contents, err := readXML(bytes.NewReader([]byte(tc.input)))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, want := len(attrs), len(tc.wantAttrs); got != want {
				t.Errorf("attributes count mismatch, got=%v, want=%v", attrs, tc.wantAttrs)
			}
			for i := range min(len(attrs), len(tc.wantAttrs)) {
				if got, want := attrs[i], tc.wantAttrs[i]; got != want {
					t.Errorf("Expected attribute got=%s, want=%s", got, want)
				}
			}
			if got, want := len(contents), len(tc.want); got != want {
				t.Errorf("contents count mismatch, got=%v, want=%v", contents, tc.want)
			}
			for i := range min(len(contents), len(tc.want)) {
				if got, want := contents[i], tc.want[i]; got != want {
					t.Errorf("Expected content got=%s, want=%s", got, want)
				}
			}
		})
	}
}
