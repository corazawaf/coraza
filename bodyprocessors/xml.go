// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package bodyprocessors

import (
	"encoding/xml"
	"io"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type xmlBodyProcessor struct {
}

func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, collections []collection.Collection, options Options) error {
	values, contents, err := readXML(reader)
	if err != nil {
		return err
	}
	col := collections[variables.RequestXML].(*collection.Map)
	col.Set("//@*", values)
	col.Set("/*", contents)
	return nil
}

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, collections []collection.Collection, options Options) error {
	return nil
}

func readXML(reader io.Reader) ([]string, []string, error) {
	var attrs []string
	var content []string
	dec := xml.NewDecoder(reader)
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
