// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bytes"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
)

func TestRequestBodyNoFilesLimitDefault(t *testing.T) {
	if got := NewWAF().RequestBodyNoFilesLimit; got != 1048576 {
		t.Fatalf("expected default 1048576, got %d", got)
	}
}

func TestRequestBodyNoFilesLimitValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		limit   int64
		wantErr bool
	}{
		"default-sized": {limit: 1048576},
		"one GiB":       {limit: _1gib},
		"zero":          {limit: 0, wantErr: true},
		"negative":      {limit: -1, wantErr: true},
		"above 1 GiB":   {limit: _1gib + 1, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			waf := NewWAF()
			waf.RequestBodyNoFilesLimit = tc.limit
			if err := waf.Validate(); (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// The write paths count every byte of a body that is not multipart as non-file
// data once a processor is selected or the body variable is forced, and refuse
// the body when the count is strictly above the limit.
func TestRequestBodyNoFilesLimitOnWrite(t *testing.T) {
	const limit = 10
	testCases := map[string]struct {
		processor string
		force     bool
		bodyLen   int
		rejected  bool
	}{
		"urlencoded at the limit":    {processor: "URLENCODED", bodyLen: limit},
		"urlencoded above the limit": {processor: "URLENCODED", bodyLen: limit + 1, rejected: true},
		"json at the limit":          {processor: "JSON", bodyLen: limit},
		"json above the limit":       {processor: "JSON", bodyLen: limit + 1, rejected: true},
		"xml above the limit":        {processor: "XML", bodyLen: limit + 1, rejected: true},
		"raw above the limit":        {processor: "RAW", bodyLen: limit + 1, rejected: true},
		"forced without processor":   {force: true, bodyLen: limit + 1, rejected: true},
		"no processor is unbounded":  {bodyLen: limit + 1},
		"multipart is not counted":   {processor: "MULTIPART", bodyLen: limit + 1},
		"lowercase multipart":        {processor: "multipart", bodyLen: limit + 1},
		"forced multipart":           {processor: "MULTIPART", force: true, bodyLen: limit + 1},
	}
	actions := map[string]types.BodyLimitAction{
		"reject":         types.BodyLimitActionReject,
		"processpartial": types.BodyLimitActionProcessPartial,
	}
	for aName, action := range actions {
		for tName, tc := range testCases {
			for wName, write := range requestBodyWriters {
				t.Run(aName+"/"+tName+"/"+wName, func(t *testing.T) {
					waf := NewWAF()
					waf.RuleEngine = types.RuleEngineOn
					waf.RequestBodyAccess = true
					waf.RequestBodyLimitAction = action
					waf.RequestBodyNoFilesLimit = limit
					tx := waf.NewTransaction()
					defer tx.Close()
					tx.ForceRequestBodyVariable = tc.force
					if tc.processor != "" {
						tx.variables.reqbodyProcessor.Set(tc.processor)
					}

					it, _, err := write(tx, strings.Repeat("a", tc.bodyLen))
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if !tc.rejected {
						if it != nil {
							t.Fatalf("unexpected interruption %+v", it)
						}
						if tx.variables.reqbodyError.Get() == "1" {
							t.Fatal("REQBODY_ERROR set for a body within the limit")
						}
						return
					}
					if it == nil || it.Status != 413 || it.Action != "deny" {
						t.Fatalf("expected a 413 deny interruption, got %+v", it)
					}
					if tx.variables.reqbodyError.Get() != "1" {
						t.Fatal("expected REQBODY_ERROR to be set")
					}
					if msg := tx.variables.reqbodyErrorMsg.Get(); !strings.Contains(msg, "no files data length is larger than the configured limit (10)") {
						t.Fatalf("unexpected REQBODY_ERROR_MSG %q", msg)
					}
				})
			}
		}
	}
}

func TestRequestBodyNoFilesLimitCountsAcrossChunks(t *testing.T) {
	waf := NewWAF()
	waf.RuleEngine = types.RuleEngineOn
	waf.RequestBodyAccess = true
	waf.RequestBodyNoFilesLimit = 10
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.variables.reqbodyProcessor.Set("JSON")

	if it, _, err := tx.WriteRequestBody([]byte("123456")); it != nil || err != nil {
		t.Fatalf("first chunk: it=%+v err=%v", it, err)
	}
	it, _, err := tx.WriteRequestBody([]byte("78901"))
	if err != nil {
		t.Fatal(err)
	}
	if it == nil || it.Status != 413 {
		t.Fatalf("expected 413 once the chunks add up above the limit, got %+v", it)
	}
}

func multipartBody(t *testing.T, fieldLen, fileLen int) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("field", strings.Repeat("f", fieldLen)); err != nil {
		t.Fatal(err)
	}
	fw, err := mw.CreateFormFile("upload", "a.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(bytes.Repeat([]byte("x"), fileLen)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return mw.FormDataContentType(), buf.Bytes()
}

// A multipart body is only measured once parsed: file bytes are excluded.
func TestRequestBodyNoFilesLimitMultipart(t *testing.T) {
	testCases := map[string]struct {
		fieldLen, fileLen int
		rejected          bool
	}{
		"large file, small field": {fieldLen: 10, fileLen: 5000},
		"small file, large field": {fieldLen: 5000, fileLen: 10, rejected: true},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			waf := NewWAF()
			waf.RuleEngine = types.RuleEngineOn
			waf.RequestBodyAccess = true
			waf.RequestBodyNoFilesLimit = 1000
			waf.UploadDir = t.TempDir()
			tx := waf.NewTransaction()
			defer tx.Close()
			ct, body := multipartBody(t, tc.fieldLen, tc.fileLen)
			tx.AddRequestHeader("content-type", ct)
			if it := tx.ProcessRequestHeaders(); it != nil {
				t.Fatalf("unexpected interruption on headers: %+v", it)
			}
			if it, _, err := tx.WriteRequestBody(body); it != nil || err != nil {
				t.Fatalf("write must not reject a multipart body: it=%+v err=%v", it, err)
			}
			it, err := tx.ProcessRequestBody()
			if err != nil {
				t.Fatal(err)
			}
			if !tc.rejected {
				if it != nil {
					t.Fatalf("unexpected interruption %+v", it)
				}
				return
			}
			if it == nil || it.Status != 413 {
				t.Fatalf("expected a 413 interruption, got %+v", it)
			}
			if tx.variables.reqbodyError.Get() != "1" {
				t.Fatal("expected REQBODY_ERROR to be set")
			}
		})
	}
}

// The no-files refusal holds when the body also crosses SecRequestBodyLimit,
// including under ProcessPartial, which would otherwise truncate and inspect.
func TestRequestBodyNoFilesLimitWithBodyLimitCrossed(t *testing.T) {
	for aName, action := range map[string]types.BodyLimitAction{
		"reject":         types.BodyLimitActionReject,
		"processpartial": types.BodyLimitActionProcessPartial,
	} {
		for wName, write := range requestBodyWriters {
			t.Run(aName+"/"+wName, func(t *testing.T) {
				waf := NewWAF()
				waf.RuleEngine = types.RuleEngineOn
				waf.RequestBodyAccess = true
				waf.RequestBodyLimit = 20
				waf.RequestBodyLimitAction = action
				waf.RequestBodyNoFilesLimit = 10
				tx := waf.NewTransaction()
				defer tx.Close()
				tx.variables.reqbodyProcessor.Set("JSON")

				it, _, err := write(tx, strings.Repeat("a", 25))
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if it == nil || it.Status != 413 {
					t.Fatalf("expected a 413 interruption, got %+v", it)
				}
				// Under Reject the body limit refuses the body before the no-files
				// count is reached; only ProcessPartial leaves that to the new check.
				if action == types.BodyLimitActionProcessPartial && tx.variables.reqbodyError.Get() != "1" {
					t.Fatal("expected REQBODY_ERROR to be set")
				}
			})
		}
	}
}

// Field names count towards the multipart total as well as values.
func TestRequestBodyNoFilesLimitMultipartCountsFieldNames(t *testing.T) {
	waf := NewWAF()
	waf.RuleEngine = types.RuleEngineOn
	waf.RequestBodyAccess = true
	waf.RequestBodyNoFilesLimit = 1000
	tx := waf.NewTransaction()
	defer tx.Close()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField(strings.Repeat("k", 600), strings.Repeat("v", 500)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	tx.AddRequestHeader("content-type", mw.FormDataContentType())
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Fatal(err)
	}
	if it == nil || it.Status != 413 {
		t.Fatalf("expected 413 for 600 key bytes + 500 value bytes over 1000, got %+v", it)
	}
}
