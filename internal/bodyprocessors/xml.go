// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/text/encoding/charmap"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type xmlBodyProcessor struct {
}

func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	values, contents, err := readXML(reader)
	if err != nil {
		return err
	}
	col := v.RequestXML()
	col.Set("//@*", values)
	col.Set("/*", contents)
	return nil
}

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return nil
}

func readXML(reader io.Reader) ([]string, []string, error) {
	var attrs []string
	var content []string
	dec := xml.NewDecoder(reader)
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity
	dec.CharsetReader = xmlCharsetReader
	for {
		token, err := dec.Token()
		if err != nil && err != io.EOF && !isUnexpectedEOFXMLSyntaxError(err) {
			return nil, nil, err
		}
		if token == nil {
			break
		}
		switch tok := token.(type) {
		case xml.StartElement:
			for _, attr := range tok.Attr {
				attrs = append(attrs, attr.Value)
			}
		case xml.CharData:
			if c := strings.TrimSpace(string(tok)); c != "" {
				content = append(content, c)
			}
		}
	}
	return attrs, content, nil
}

func isUnexpectedEOFXMLSyntaxError(err error) bool {
	var serr *xml.SyntaxError
	return errors.As(err, &serr) && serr.Msg == "unexpected EOF"
}

// xmlCharsetReader is used by the XML decoder for bodies declaring an encoding
// other than UTF-8. Labels are matched case-insensitively against the IANA
// names and aliases of the supported encodings:
//   - ISO-8859-1 is decoded as strict Latin-1 (charmap.ISO8859_1), so 0x80-0x9F
//     become the C1 controls U+0080-U+009F. Unlike WHATWG, which treats these
//     labels as windows-1252, the declared encoding is honored as XML requires.
//   - windows-1252 is decoded with charmap.Windows1252.
//   - US-ASCII passes the input through and fails at the first non-ASCII byte.
//
// Any other encoding results in an error.
func xmlCharsetReader(label string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "iso-8859-1", "iso8859-1", "iso88591", "iso_8859-1", "iso_8859-1:1987",
		"iso-ir-100", "latin1", "latin-1", "l1", "ibm819", "cp819", "csisolatin1":
		return charmap.ISO8859_1.NewDecoder().Reader(input), nil
	case "windows-1252", "cp1252", "x-cp1252", "cswindows1252":
		return charmap.Windows1252.NewDecoder().Reader(input), nil
	case "us-ascii", "ascii", "us", "iso-ir-6", "ansi_x3.4-1968", "ansi_x3.4-1986",
		"iso_646.irv:1991", "iso646-us", "ibm367", "cp367", "csascii":
		return &asciiReader{r: input}, nil
	}
	return nil, fmt.Errorf("unsupported XML encoding %q", label)
}

// asciiReader passes US-ASCII input through unchanged and fails at the first
// byte outside the ASCII range, returning only the valid bytes before it.
// x/text has no strict US-ASCII decoder: ianaindex replaces such bytes with
// U+FFFD and WHATWG decodes them as windows-1252.
type asciiReader struct {
	r   io.Reader
	err error
}

// Read reads from the underlying reader and returns an error once a non-ASCII
// byte is found.
func (a *asciiReader) Read(p []byte) (int, error) {
	if a.err != nil {
		return 0, a.err
	}
	n, err := a.r.Read(p)
	for i, b := range p[:n] {
		if b > 0x7f {
			a.err = fmt.Errorf("invalid US-ASCII byte 0x%02x", b)
			return i, a.err
		}
	}
	return n, err
}

var (
	_ plugintypes.BodyProcessor = &xmlBodyProcessor{}
)

func init() {
	RegisterBodyProcessor("xml", func() plugintypes.BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
