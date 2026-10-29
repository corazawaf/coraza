// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
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

// xmlCharsetReader is used by the XML decoder for bodies declaring an encoding
// other than UTF-8. Only US-ASCII and ISO-8859-1 are supported, as both map
// each byte to the Unicode code point of the same value. Any other encoding
// results in an error.
func xmlCharsetReader(label string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(label) {
	case "iso-8859-1", "iso8859-1", "latin1", "us-ascii", "ascii":
		return newLatin1Reader(input), nil
	}
	return nil, fmt.Errorf("unsupported XML encoding %q", label)
}

// latin1Reader converts ISO-8859-1 input into UTF-8.
type latin1Reader struct {
	r       io.Reader
	src     []byte
	out     []byte
	pending []byte
	err     error
}

func newLatin1Reader(r io.Reader) *latin1Reader {
	return &latin1Reader{r: r}
}

func (l *latin1Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(l.pending) == 0 {
		if l.err != nil {
			return 0, l.err
		}
		// Each input byte expands to at most two output bytes.
		size := max(len(p)/2, 1)
		if cap(l.src) < size {
			l.src = make([]byte, size)
		}
		n, err := l.r.Read(l.src[:size])
		l.err = err
		l.out = l.out[:0]
		for _, b := range l.src[:n] {
			l.out = utf8.AppendRune(l.out, rune(b))
		}
		l.pending = l.out
	}
	n := copy(p, l.pending)
	l.pending = l.pending[n:]
	return n, nil
}

var (
	_ plugintypes.BodyProcessor = &xmlBodyProcessor{}
)

func init() {
	RegisterBodyProcessor("xml", func() plugintypes.BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
