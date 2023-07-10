// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

func TestHTTPSAuditLog(t *testing.T) {
	writer := &httpsWriter{}
	formatter := nativeFormatter
	pts, err := types.ParseAuditLogParts("ABCDEZ")
	if err != nil {
		t.Fatal(err)
	}
	al := &Log{
		Parts_: pts,

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
	// we create a test http server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.ContentLength == 0 {
			t.Fatal("ContentLength is 0")
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
	if err := writer.Write(al); err != nil {
		t.Fatal(err)
	}
}
