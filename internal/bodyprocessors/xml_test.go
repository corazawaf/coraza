// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"bytes"
	"io"
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
	testCases := []struct {
		Name      string
		Input     string
		WantAttrs []string
		Want      []string
	}{
		{
			Name:      "ISO-8859-1 with ASCII content",
			Input:     `<?xml version="1.0" encoding="ISO-8859-1"?><customer id="42"><name>Renee</name></customer>`,
			WantAttrs: []string{"42"},
			Want:      []string{"Renee"},
		},
		{
			Name:      "ISO-8859-1 with Latin-1 content",
			Input:     "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?><customer city=\"M\xfcnchen\"><name>Ren\xe9e</name></customer>",
			WantAttrs: []string{"München"},
			Want:      []string{"Renée"},
		},
		{
			Name:      "latin1 label",
			Input:     "<?xml version=\"1.0\" encoding=\"Latin1\"?><a>\xff\xa0x</a>",
			WantAttrs: nil,
			Want:      []string{"ÿ x"},
		},
		{
			Name:      "US-ASCII",
			Input:     `<?xml version="1.0" encoding="US-ASCII"?><a b="c">d</a>`,
			WantAttrs: []string{"c"},
			Want:      []string{"d"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			attrs, contents, err := readXML(bytes.NewReader([]byte(tc.Input)))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(attrs, tc.WantAttrs) {
				t.Errorf("unexpected attributes, got=%q, want=%q", attrs, tc.WantAttrs)
			}
			if !slices.Equal(contents, tc.Want) {
				t.Errorf("unexpected contents, got=%q, want=%q", contents, tc.Want)
			}
		})
	}
}

func TestXMLUnsupportedEncoding(t *testing.T) {
	xmldoc := `<?xml version="1.0" encoding="Shift_JIS"?><a>b</a>`
	if _, _, err := readXML(bytes.NewReader([]byte(xmldoc))); err == nil {
		t.Error("expected an error for an unsupported encoding")
	}
}

func TestLatin1ReaderSmallBuffer(t *testing.T) {
	r := newLatin1Reader(bytes.NewReader([]byte("a\xe9\xffb")))
	var out []byte
	p := make([]byte, 1)
	for {
		n, err := r.Read(p)
		out = append(out, p[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if got, want := string(out), "aéÿb"; got != want {
		t.Errorf("unexpected output, got=%q, want=%q", got, want)
	}
}
