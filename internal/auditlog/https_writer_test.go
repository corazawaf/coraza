// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

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

func TestHTTPAuditLog(t *testing.T) {
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
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-coraza") {
			t.Fatalf("Content-Type is not application/x-coraza, got %s", ct)
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
			t.Fatalf("Body does not match, got:\n%s", string(body))
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

func TestJSONAuditHTTP(t *testing.T) {
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

func TestOCSFAuditHTTP(t *testing.T) {
	writer := &httpsWriter{}
	formatter := &ocsfFormatter{}
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

func TestHTTPSWriterClose(t *testing.T) {
	t.Run("before init", func(t *testing.T) {
		writer := &httpsWriter{}
		if err := writer.Close(); err != nil {
			t.Fatalf("unexpected error closing uninitialized httpsWriter: %v", err)
		}
	})

	t.Run("after init and write", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		writer := &httpsWriter{}
		if err := writer.Init(plugintypes.AuditLogConfig{
			Target:    server.URL,
			Formatter: &jsonFormatter{},
		}); err != nil {
			t.Fatal(err)
		}
		if err := writer.Write(sampleHttpsAuditLog); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("unexpected error closing initialized httpsWriter: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("unexpected error closing httpsWriter a second time: %v", err)
		}
	})
}
