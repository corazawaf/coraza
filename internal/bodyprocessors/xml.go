// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
)

type xmlBodyProcessor struct {
}

func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	values, contents, truncated, err := readXML(reader, options.ArgumentLimit)
	if err != nil {
		return err
	}
	col := v.RequestXML()
	col.Set("//@*", values)
	col.Set("/*", contents)
	if truncated {
		if alr := v.ArgumentsLimitReached(); alr != nil {
			alr.(*collections.Single).Set("1")
		}
	}
	return nil
}

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	values, contents, truncated, err := readXML(reader, options.ArgumentLimit)
	if err != nil {
		return err
	}
	col := v.ResponseXML()
	col.Set("//@*", values)
	col.Set("/*", contents)
	if truncated {
		if alr := v.ArgumentsLimitReached(); alr != nil {
			alr.(*collections.Single).Set("1")
		}
	}
	return nil
}

func readXML(reader io.Reader, limit int) ([]string, []string, bool, error) {
	var attrs []string
	var content []string
	dec := xml.NewDecoder(reader)
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity
	truncated := false
	for {
		token, err := dec.Token()
		if err != nil && err != io.EOF && !isUnexpectedEOFXMLSyntaxError(err) {
			return nil, nil, false, err
		}
		if token == nil {
			break
		}
		switch tok := token.(type) {
		case xml.StartElement:
			for _, attr := range tok.Attr {
				if limit > 0 && len(attrs)+len(content) >= limit {
					truncated = true
					break
				}
				attrs = append(attrs, attr.Value)
			}
		case xml.CharData:
			if c := strings.TrimSpace(string(tok)); c != "" {
				if limit > 0 && len(attrs)+len(content) >= limit {
					truncated = true
				} else {
					content = append(content, c)
				}
			}
		}
		if truncated {
			break
		}
	}
	return attrs, content, truncated, nil
}

func isUnexpectedEOFXMLSyntaxError(err error) bool {
	var serr *xml.SyntaxError
	return errors.As(err, &serr) && serr.Msg == "unexpected EOF"
}

var (
	_ plugintypes.BodyProcessor = &xmlBodyProcessor{}
)

func init() {
	RegisterBodyProcessor("xml", func() plugintypes.BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
