// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

/*
func TestFormatters(t *testing.T) {
	al := createAuditLog()
	type tcase struct {
		Log Log
		Output   string
	}
	cases := map[string][]tcase{
		"cef": {
			{al, "02/Jan/2006:15:04:20 -0700 localhost CEF:0|coraza|coraza-waf|v1.2|n/a|n/a|0|src= status=200"},
		},
	}

	for format, cases := range cases {
		f, err := getLogFormatter(format)
		if err != nil {
			t.Error(err)
		}
		for _, c := range cases {
			if out, err := f(c.Log); err != nil {
				t.Error(err)
			} else if string(out) != c.Output {
				//TODO, as the result is a map, it is not ordered and anything can happen :(
				//t.Errorf("failed to match log formatter %s, \ngot: %s\nexpected: %s", format, out, c.Output)
			}
		}
	}
}

func TestModsecBoundary(t *testing.T) {
	// TODO...
}

*/

func TestLegacyFormatter(t *testing.T) {
	al := createAuditLog()
	f := &legacyJSONFormatter{}
	data, err := f.Format(al)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(f.MIME(), "json") {
		t.Errorf("failed to match MIME, expected json and got %s", f.MIME())
	}
	var legacyAl logLegacy
	if err := json.Unmarshal(data, &legacyAl); err != nil {
		t.Error(err)
	}
	if legacyAl.Transaction.Time != al.Transaction().Timestamp() {
		t.Errorf("failed to match legacy formatter, \ngot: %s\nexpected: %s", legacyAl.Transaction.Time, al.Transaction().Timestamp())
	}
	// validate transaction ID
	if legacyAl.Transaction.TransactionID != al.Transaction().ID() {
		t.Errorf("failed to match legacy formatter, \ngot: %s\nexpected: %s", legacyAl.Transaction.TransactionID, al.Transaction().ID())
	}
	if legacyAl.AuditData.Messages[0] != "some message" {
		t.Errorf("failed to match legacy formatter, \ngot: %s\nexpected: %s", legacyAl.AuditData.Messages[0], "some message")
	}
}

// jsonFile mirrors TransactionRequestFiles for JSON unmarshaling,
// since the interface type cannot be deserialized directly.
type jsonFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Mime string `json:"mime"`
}

// jsonLog is a minimal struct for unmarshaling the JSON formatter output
// relevant to Part J testing.
type jsonLog struct {
	Transaction struct {
		Request struct {
			Files []jsonFile `json:"files"`
		} `json:"request"`
	} `json:"transaction"`
}

func TestJSONFormatterPartJ(t *testing.T) {
	f := &jsonFormatter{}

	tests := []struct {
		name          string
		inputFiles    []plugintypes.AuditLogTransactionRequestFiles
		expectedFiles []jsonFile
	}{
		{
			name: "uploaded files included in JSON output",
			inputFiles: []plugintypes.AuditLogTransactionRequestFiles{
				TransactionRequestFiles{Name_: "image.png", Size_: 12345, Mime_: "image/png"},
				TransactionRequestFiles{Name_: "doc.pdf", Size_: 67890, Mime_: "application/pdf"},
			},
			expectedFiles: []jsonFile{
				{Name: "image.png", Size: 12345, Mime: "image/png"},
				{Name: "doc.pdf", Size: 67890, Mime: "application/pdf"},
			},
		},
		{
			name:          "no files produces empty array",
			inputFiles:    []plugintypes.AuditLogTransactionRequestFiles{},
			expectedFiles: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			al := &Log{
				Parts_: []types.AuditLogPart{
					types.AuditLogPartUploadedFiles,
				},
				Transaction_: Transaction{
					Request_: &TransactionRequest{
						Files_: tc.inputFiles,
					},
				},
			}

			data, err := f.Format(al)
			if err != nil {
				t.Fatal(err)
			}

			var parsed jsonLog
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatal(err)
			}

			files := parsed.Transaction.Request.Files
			if len(files) != len(tc.expectedFiles) {
				t.Fatalf("expected %d files, got %d", len(tc.expectedFiles), len(files))
			}
			for i, expected := range tc.expectedFiles {
				if files[i].Name != expected.Name {
					t.Errorf("file %d: expected name %s, got %s", i, expected.Name, files[i].Name)
				}
				if files[i].Size != expected.Size {
					t.Errorf("file %d: expected size %d, got %d", i, expected.Size, files[i].Size)
				}
				if files[i].Mime != expected.Mime {
					t.Errorf("file %d: expected mime %s, got %s", i, expected.Mime, files[i].Mime)
				}
			}
		})
	}
}
