// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"bufio"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

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

// xmlCharsetReader decodes bodies that declare ISO-8859-1 or US-ASCII (all IANA
// names and aliases, plus "ascii"). Both map each byte to the code point of the
// same value.
// Any other encoding returns an error, so the body still sets REQBODY_ERROR.
func xmlCharsetReader(label string, input io.Reader) (io.Reader, error) {
	ascii := false
	switch strings.ToLower(label) {
	case "iso_8859-1:1987", "iso-ir-100", "iso_8859-1", "iso-8859-1", "latin1", "l1", "ibm819", "cp819", "csisolatin1":
	case "us-ascii", "iso-ir-6", "ansi_x3.4-1968", "ansi_x3.4-1986", "iso_646.irv:1991", "iso646-us", "us", "ibm367", "cp367", "csascii", "ascii":
		ascii = true
	default:
		return nil, fmt.Errorf("unsupported XML encoding %q", label)
	}
	br, ok := input.(io.ByteReader)
	if !ok {
		br = bufio.NewReader(input)
	}
	return &latin1Reader{r: br, ascii: ascii}, nil
}

// latin1Reader converts ISO-8859-1 to UTF-8 one byte at a time. It implements
// io.ByteReader, so encoding/xml reads from it directly without another buffer.
// In US-ASCII mode a byte above 0x7F is an error, as the XML spec requires for
// content that does not match the declared encoding.
type latin1Reader struct {
	r     io.ByteReader
	ascii bool
	next  byte // pending second byte of a two-byte UTF-8 sequence, 0 if none
}

func (l *latin1Reader) ReadByte() (byte, error) {
	if l.next != 0 {
		b := l.next
		l.next = 0
		return b, nil
	}
	b, err := l.r.ReadByte()
	if err != nil || b < utf8.RuneSelf {
		return b, err
	}
	if l.ascii {
		return 0, fmt.Errorf("byte 0x%02x is not US-ASCII", b)
	}
	l.next = 0x80 | b&0x3f
	return 0xc0 | b>>6, nil
}

func (l *latin1Reader) Read(p []byte) (int, error) {
	for i := range p {
		b, err := l.ReadByte()
		if err != nil {
			return i, err
		}
		p[i] = b
	}
	return len(p), nil
}

var (
	_ plugintypes.BodyProcessor = &xmlBodyProcessor{}
	_ io.ByteReader             = (*latin1Reader)(nil)
)

func init() {
	RegisterBodyProcessor("xml", func() plugintypes.BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
