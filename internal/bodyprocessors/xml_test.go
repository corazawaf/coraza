// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"bytes"
	"slices"
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

func TestXMLDeclaredEncoding(t *testing.T) {
	decl := func(enc string) string { return `<?xml version="1.0" encoding="` + enc + `"?>` }
	tests := []struct {
		name      string
		body      string
		wantAttrs []string
		wantText  []string
		wantErr   bool
	}{
		{name: "UTF-8", body: decl("UTF-8") + `<a b="x">Renée</a>`, wantAttrs: []string{"x"}, wantText: []string{"Renée"}},
		{name: "ISO-8859-1 with ASCII content", body: decl("ISO-8859-1") + `<a b="x">Renee</a>`, wantAttrs: []string{"x"}, wantText: []string{"Renee"}},
		{name: "ISO-8859-1 with Latin-1 content", body: decl("ISO-8859-1") + "<a b=\"K\xf8benhavn\">Ren\xe9e</a>", wantAttrs: []string{"København"}, wantText: []string{"Renée"}},
		{name: "ISO-8859-1 maps 0x80-0x9F to C1 controls", body: decl("ISO-8859-1") + "<a>\x80\x9f</a>", wantText: []string{"\u0080\u009f"}},
		{name: "alias latin1, any case", body: decl("Latin1") + "<a>\xe9</a>", wantText: []string{"é"}},
		{name: "alias iso-ir-100", body: decl("iso-ir-100") + "<a>\xe9</a>", wantText: []string{"é"}},
		{name: "US-ASCII", body: decl("US-ASCII") + `<a b="x">Renee</a>`, wantAttrs: []string{"x"}, wantText: []string{"Renee"}},
		{name: "alias ANSI_X3.4-1986", body: decl("ANSI_X3.4-1986") + "<a>Renee</a>", wantText: []string{"Renee"}},
		{name: "US-ASCII with a non-ASCII byte", body: decl("US-ASCII") + "<a>Ren\xe9e</a>", wantErr: true},
		{name: "unsupported encoding", body: decl("Shift_JIS") + "<a>x</a>", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, text, err := readXML(bytes.NewReader([]byte(tt.body)))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !slices.Equal(attrs, tt.wantAttrs) || !slices.Equal(text, tt.wantText) {
				t.Errorf("got attrs %q text %q, want %q %q", attrs, text, tt.wantAttrs, tt.wantText)
			}
		})
	}
}

// TestXMLCharsetReaderLabels covers registry names that are not valid XML
// encoding names (EncName has no ':'), so they are tested on the reader directly.
func TestXMLCharsetReaderLabels(t *testing.T) {
	for _, label := range []string{"ISO_8859-1:1987", "ISO_646.irv:1991"} {
		if _, err := xmlCharsetReader(label, bytes.NewReader(nil)); err != nil {
			t.Errorf("xmlCharsetReader(%q): %v", label, err)
		}
	}
}
