// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package bodyprocessors

import (
	"encoding/xml"
	"io"
	"strings"

	"github.com/corazawaf/coraza/v3/rules"
)

type xmlBodyProcessor struct {
}

func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, v rules.TransactionVariables, options Options) error {
	values, contents, err := readXML(reader, false)
	if err != nil {
		return err
	}
	col := v.RequestXML()
	col.Set("//@*", values)
	col.Set("/*", contents)
	return nil
}

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, v rules.TransactionVariables, options Options) error {
	return nil
}

func readXML(reader io.Reader, strict bool) ([]string, []string, error) {
	var attrs []string
	var content []string
	dec := xml.NewDecoder(reader)
	if !strict {
		dec.Strict = false
		dec.AutoClose = xml.HTMLAutoClose
		dec.Entity = xml.HTMLEntity
	}
	for {
		token, err := dec.Token()
		if err != nil && err != io.EOF {
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

var (
	_ BodyProcessor = &xmlBodyProcessor{}
)

func init() {
	Register("xml", func() BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
