// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

var sampleHttpsAuditLog = &Log{

	Transaction_: Transaction{
		ID_: "test123",
	},
	Messages_: []plugintypes.AuditLogMessage{
		Message{
			Data_: &MessageData{
				ID_:  100,
				Raw_: "SecAction \"id:100\"",
			},
		},
	},
}

func TestHTTPSAuditLog(t *testing.T) {
	writer := &httpsWriter{}
	formatter := &nativeFormatter{}
	pts, err := types.ParseAuditLogParts("ABCDEZ")
	if err != nil {
		t.Fatal(err)
	}
	sampleHttpsAuditLog.Parts_ = pts
	// we create a test http server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.ContentLength == 0 {
			t.Fatal("ContentLength is 0")
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/octet-stream") {
			t.Fatalf("Content-Type is not application/octet-stream, got %s", ct)
		}
		// now we get the body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) == 0 {
			t.Fatal("Body is empty")
		}
		if !bytes.Contains(body, []byte("test123")) {
			t.Fatal("Body does not match")
		}
	}))
	defer server.Close()
	if err := writer.Init(plugintypes.AuditLogConfig{
		Target:    server.URL,
		Formatter: formatter,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(sampleHttpsAuditLog); err != nil {
		t.Fatal(err)
	}
}

func TestJSONAuditHTTPS(t *testing.T) {
	writer := &httpsWriter{}
	formatter := &jsonFormatter{}
	// we create a test http server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.ContentLength == 0 {
			t.Fatal("ContentLength is 0")
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("Content-Type is not application/json, got %s", ct)
		}
	}))
	defer server.Close()
	if err := writer.Init(plugintypes.AuditLogConfig{
		Target:    server.URL,
		Formatter: formatter,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(sampleHttpsAuditLog); err != nil {
		t.Fatal(err)
	}
}
