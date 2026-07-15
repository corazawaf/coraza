// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

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

func TestLibModSecurityJSONFormatter(t *testing.T) {
	timestamp := time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC).UnixNano()
	al := &Log{
		Parts_: types.AuditLogParts("BCEFH"),
		Transaction_: Transaction{
			Timestamp_:     "2024/01/02 03:04:05",
			UnixTimestamp_: timestamp,
			ID_:            "tx-id",
			ClientIP_:      "127.0.0.1",
			ClientPort_:    1234,
			HostIP_:        "127.0.0.2",
			HostPort_:      443,
			ServerID_:      "example.test",
			IsInterrupted_: true,
			Request_: &TransactionRequest{
				Method_:      "GET",
				URI_:         "/?x=/etc/passwd",
				Protocol_:    "HTTP/1.1",
				HTTPVersion_: "HTTP/1.1",
				Body_:        "request body",
				Headers_: map[string][]string{
					"host":   {"example.test"},
					"x-test": {"one", "two"},
				},
			},
			Response_: &TransactionResponse{
				Status_: 403,
				Body_:   "response body",
				Headers_: map[string][]string{
					"content-type": {"text/plain"},
				},
			},
			Producer_: &TransactionProducer{
				Connector_:  "coraza-spoa",
				Version_:    "v1.0.0",
				RuleEngine_: "On",
				Rulesets_:   []string{"OWASP_CRS/4.0.0"},
			},
		},
		Messages_: []plugintypes.AuditLogMessage{
			Message{
				Message_: "OS File Access Attempt",
				Data_: &MessageData{
					Match_:     "Matched \"Operator `PmFromFile' against variable `ARGS:x'\"",
					Reference_: "o1,10v8,11",
					File_:      "/rules/lfi.conf",
					Line_:      79,
					ID_:        930120,
					Data_:      "Matched Data: etc/passwd",
					Severity_:  types.RuleSeverityCritical,
					Ver_:       "OWASP_CRS/4.0.0",
					Tags_:      []string{"attack-lfi"},
				},
			},
		},
	}

	data, err := (&libmodsecurityJSONFormatter{}).Format(al)
	if err != nil {
		t.Fatal(err)
	}

	var got libmodsecurityJSONLog
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}

	transaction := got.Transaction
	if want := time.Unix(0, timestamp).Format(time.ANSIC); transaction.Timestamp != want {
		t.Fatalf("expected time_stamp %q, got %q", want, transaction.Timestamp)
	}
	if transaction.UniqueID != "tx-id" {
		t.Fatalf("expected unique_id %q, got %q", "tx-id", transaction.UniqueID)
	}
	if transaction.Request.HTTPVersion != "1.1" {
		t.Fatalf("expected HTTP version %q, got %q", "1.1", transaction.Request.HTTPVersion)
	}
	if transaction.Request.Body == nil || *transaction.Request.Body != "request body" {
		t.Fatalf("expected request body, got %#v", transaction.Request.Body)
	}
	if transaction.Request.Headers == nil || (*transaction.Request.Headers)["x-test"] != "one, two" {
		t.Fatalf("expected flattened request headers, got %#v", transaction.Request.Headers)
	}
	if transaction.Response.HTTPCode != 403 {
		t.Fatalf("expected response http_code %d, got %d", 403, transaction.Response.HTTPCode)
	}
	if transaction.Response.Body == nil || *transaction.Response.Body != "response body" {
		t.Fatalf("expected response body, got %#v", transaction.Response.Body)
	}
	if transaction.Producer == nil {
		t.Fatal("expected producer")
	}
	if transaction.Producer.ModSecurity != libmodsecurityJSONProducerName {
		t.Fatalf("expected modsecurity producer %q, got %q", libmodsecurityJSONProducerName, transaction.Producer.ModSecurity)
	}
	if transaction.Producer.Connector != "coraza-spoa v1.0.0" {
		t.Fatalf("expected connector %q, got %q", "coraza-spoa v1.0.0", transaction.Producer.Connector)
	}
	if transaction.Producer.SecRulesEngine != "Enabled" {
		t.Fatalf("expected secrules_engine %q, got %q", "Enabled", transaction.Producer.SecRulesEngine)
	}
	if transaction.Messages == nil || len(*transaction.Messages) != 1 {
		t.Fatalf("expected one message, got %#v", transaction.Messages)
	}
	if got := (*transaction.Messages)[0].Details.RuleID; got != "930120" {
		t.Fatalf("expected ruleId %q, got %q", "930120", got)
	}
	if got := (*transaction.Messages)[0].Details.Reference; got != "o1,10v8,11" {
		t.Fatalf("expected reference %q, got %q", "o1,10v8,11", got)
	}
	if got := (*transaction.Messages)[0].Details.Match; got != "Matched \"Operator `PmFromFile' against variable `ARGS:x'\"" {
		t.Fatalf("expected match text, got %q", got)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["messages"]; ok {
		t.Fatal("expected messages under transaction, not at top level")
	}
	rawTransaction := raw["transaction"].(map[string]any)
	if _, ok := rawTransaction["timestamp"]; ok {
		t.Fatal("expected libmodsecurity time_stamp key, not Coraza timestamp key")
	}
	if _, ok := rawTransaction["id"]; ok {
		t.Fatal("expected libmodsecurity unique_id key, not Coraza id key")
	}
}

func TestLibModSecurityJSONFormatterHonorsParts(t *testing.T) {
	al := &Log{
		Parts_: types.AuditLogParts("A"),
		Transaction_: Transaction{
			Request_: &TransactionRequest{
				Body_:    "request body",
				Headers_: map[string][]string{"host": {"example.test"}},
			},
			Response_: &TransactionResponse{
				Status_:  403,
				Body_:    "response body",
				Headers_: map[string][]string{"content-type": {"text/plain"}},
			},
			Producer_: &TransactionProducer{
				RuleEngine_: "DetectionOnly",
			},
		},
	}

	data, err := (&libmodsecurityJSONFormatter{}).Format(al)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	transaction := raw["transaction"].(map[string]any)
	request := transaction["request"].(map[string]any)
	response := transaction["response"].(map[string]any)
	for _, key := range []string{"body", "headers"} {
		if _, ok := request[key]; ok {
			t.Fatalf("expected request %s to be omitted without its audit part", key)
		}
		if _, ok := response[key]; ok {
			t.Fatalf("expected response %s to be omitted without its audit part", key)
		}
	}
	if _, ok := transaction["producer"]; ok {
		t.Fatal("expected producer to be omitted without part H")
	}
	if _, ok := transaction["messages"]; ok {
		t.Fatal("expected messages to be omitted without part H")
	}

	al.Parts_ = types.AuditLogParts("H")
	data, err = (&libmodsecurityJSONFormatter{}).Format(al)
	if err != nil {
		t.Fatal(err)
	}
	raw = nil
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	transaction = raw["transaction"].(map[string]any)
	if _, ok := transaction["producer"]; !ok {
		t.Fatal("expected producer with part H")
	}
	messages, ok := transaction["messages"].([]any)
	if !ok || len(messages) != 0 {
		t.Fatalf("expected empty messages array with part H, got %#v", transaction["messages"])
	}
}

func TestLibModSecurityJSONFormatterRegistered(t *testing.T) {
	formatter, err := GetFormatter("ModSecurityV3")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := formatter.(*libmodsecurityJSONFormatter); !ok {
		t.Fatalf("expected ModSecurityV3 formatter, got %T", formatter)
	}
}
