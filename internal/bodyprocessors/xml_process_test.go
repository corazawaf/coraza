// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
	"io"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/collection"
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

func TestXMLProcess(t *testing.T) {
	tests := []struct {
		name         string
		isResponse   bool
		body         io.Reader
		wantErr      bool
		wantAttrs    int
		wantContents []string
	}{
		{
			name:         "process request succeeds",
			isResponse:   false,
			body:         strings.NewReader(`<bookstore><book id="1" secret="value"><title>Harry Potter</title></book></bookstore>`),
			wantAttrs:    2,
			wantContents: []string{"Harry Potter"},
		},
		{
			name:         "process response succeeds",
			isResponse:   true,
			body:         strings.NewReader(`<response status="ok" code="200"><data>SecretPayload</data></response>`),
			wantAttrs:    2,
			wantContents: []string{"SecretPayload"},
		},
		{
			name:       "process request reader error",
			isResponse: false,
			body:       errReader{},
			wantErr:    true,
		},
		{
			name:       "process response reader error",
			isResponse: true,
			body:       errReader{},
			wantErr:    true,
		},
	}

	bp := xmlProcessor(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := corazawaf.NewTransactionVariables()
			var err error
			if tt.isResponse {
				err = bp.ProcessResponse(tt.body, v, plugintypes.BodyProcessorOptions{})
			} else {
				err = bp.ProcessRequest(tt.body, v, plugintypes.BodyProcessorOptions{})
			}

			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error status: got %v, wantErr: %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			var col collection.Map
			if tt.isResponse {
				col = v.ResponseXML()
			} else {
				col = v.RequestXML()
			}

			attrs := col.Get("//@*")
			if len(attrs) != tt.wantAttrs {
				t.Errorf("expected %d attributes, got %d", tt.wantAttrs, len(attrs))
			}
			contents := col.Get("/*")
			if len(contents) != len(tt.wantContents) {
				t.Errorf("expected %v contents, got %v", tt.wantContents, contents)
			} else {
				for i, want := range tt.wantContents {
					if contents[i] != want {
						t.Errorf("contents[%d] = %q, want %q", i, contents[i], want)
					}
				}
			}
		})
	}
}
