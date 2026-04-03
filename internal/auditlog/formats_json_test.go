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

	t.Run("uploaded files included in JSON output", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartUploadedFiles,
			},
			Transaction_: Transaction{
				Timestamp_:     "02/Jan/2006:15:04:20 -0700",
				UnixTimestamp_: 0,
				ID_:            "456",
				Request_: &TransactionRequest{
					URI_:      "/upload",
					Method_:   "POST",
					Protocol_: "HTTP/1.1",
					Files_: []plugintypes.AuditLogTransactionRequestFiles{
						TransactionRequestFiles{Name_: "image.png", Size_: 12345, Mime_: "image/png"},
						TransactionRequestFiles{Name_: "doc.pdf", Size_: 67890, Mime_: "application/pdf"},
					},
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
		if len(files) != 2 {
			t.Fatalf("expected 2 files, got %d", len(files))
		}
		if files[0].Name != "image.png" {
			t.Errorf("expected file name image.png, got %s", files[0].Name)
		}
		if files[0].Size != 12345 {
			t.Errorf("expected file size 12345, got %d", files[0].Size)
		}
		if files[0].Mime != "image/png" {
			t.Errorf("expected mime image/png, got %s", files[0].Mime)
		}
		if files[1].Name != "doc.pdf" {
			t.Errorf("expected file name doc.pdf, got %s", files[1].Name)
		}
		if files[1].Size != 67890 {
			t.Errorf("expected file size 67890, got %d", files[1].Size)
		}
	})

	t.Run("no files produces empty array", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartUploadedFiles,
			},
			Transaction_: Transaction{
				ID_: "789",
				Request_: &TransactionRequest{
					Files_: []plugintypes.AuditLogTransactionRequestFiles{},
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

		if len(parsed.Transaction.Request.Files) != 0 {
			t.Errorf("expected 0 files, got %d", len(parsed.Transaction.Request.Files))
		}
	})
}
