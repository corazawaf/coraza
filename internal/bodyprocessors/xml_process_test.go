// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func xmlProcessor(t *testing.T) plugintypes.BodyProcessor {
	t.Helper()
	bp, err := bodyprocessors.GetBodyProcessor("xml")
	if err != nil {
		t.Fatal(err)
	}
	return bp
}

func TestXMLProcessRequest(t *testing.T) {
	bp := xmlProcessor(t)
	v := corazawaf.NewTransactionVariables()

	body := `<bookstore><book id="1" secret="value"><title>Harry Potter</title></book></bookstore>`
	if err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{}); err != nil {
		t.Fatal(err)
	}

	attrs := v.RequestXML().Get("//@*")
	if len(attrs) != 2 {
		t.Errorf("Expected 2 attributes in RequestXML, got %d", len(attrs))
	}
	contents := v.RequestXML().Get("/*")
	if len(contents) != 1 || contents[0] != "Harry Potter" {
		t.Errorf("Expected ['Harry Potter'] in RequestXML, got %v", contents)
	}
}

func TestXMLProcessResponse(t *testing.T) {
	bp := xmlProcessor(t)
	v := corazawaf.NewTransactionVariables()

	body := `<response status="ok" code="200"><data>SecretPayload</data></response>`
	if err := bp.ProcessResponse(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{}); err != nil {
		t.Fatal(err)
	}

	attrs := v.ResponseXML().Get("//@*")
	if len(attrs) != 2 {
		t.Errorf("Expected 2 attributes in ResponseXML, got %d", len(attrs))
	}
	contents := v.ResponseXML().Get("/*")
	if len(contents) != 1 || contents[0] != "SecretPayload" {
		t.Errorf("Expected ['SecretPayload'] in ResponseXML, got %v", contents)
	}
}

func TestXMLProcessRequestReaderError(t *testing.T) {
	bp := xmlProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := bp.ProcessRequest(errReader{}, v, plugintypes.BodyProcessorOptions{})
	if err == nil {
		t.Fatal("expected error from failing reader, got nil")
	}
}

func TestXMLProcessResponseReaderError(t *testing.T) {
	bp := xmlProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := bp.ProcessResponse(errReader{}, v, plugintypes.BodyProcessorOptions{})
	if err == nil {
		t.Fatal("expected error from failing reader, got nil")
	}
}
