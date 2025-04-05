// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type xmlBodyProcessor struct {
}

func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	// Read the entire body to store it raw
	buf := new(bytes.Buffer)
	tee := io.TeeReader(reader, buf)

	// Process XML as before
	values, contents, err := readXML(tee)
	if err != nil {
		return err
	}

	// Store standard structure
	col := v.RequestXML()
	col.Set("//@*", values)
	col.Set("/*", contents)

	// Store the raw XML in the TX variable for validateSchema to use
	rawXml := buf.String()
	if txVar := v.TX(); txVar != nil && v.RequestBody() != nil {
		// Store the content type and raw body
		txVar.Set("xml_request_body", []string{rawXml})
	}

	// Also store in the XML variable for backward compatibility
	if xmlVar := v.RequestXML(); xmlVar != nil {
		xmlVar.Set("raw", []string{rawXml})
	}

	return nil
}

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	// Read the entire body to store it raw
	buf := new(bytes.Buffer)
	tee := io.TeeReader(reader, buf)

	// Process XML as before
	values, contents, err := readXML(tee)
	if err != nil {
		return err
	}

	// Store standard structure
	col := v.ResponseXML()
	col.Set("//@*", values)
	col.Set("/*", contents)

	// Store the raw XML in the TX variable for validateSchema to use
	rawXml := buf.String()
	if txVar := v.TX(); txVar != nil && v.ResponseBody() != nil {
		// Store the content type and raw body
		txVar.Set("xml_response_body", []string{rawXml})
	}

	// Also store in the XML variable for backward compatibility
	if xmlVar := v.XML(); xmlVar != nil {
		xmlVar.Set("raw", []string{rawXml})
	}

	return nil
}

func readXML(reader io.Reader) ([]string, []string, error) {
	var attrs []string
	var content []string
	dec := xml.NewDecoder(reader)
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity
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
	_ plugintypes.BodyProcessor = &xmlBodyProcessor{}
)

func init() {
	RegisterBodyProcessor("xml", func() plugintypes.BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
