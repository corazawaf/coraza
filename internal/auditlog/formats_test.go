// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"bytes"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

func TestNativeFormatter(t *testing.T) {
	al := createAuditLog()
	data, err := nativeFormatter(al)
	if err != nil {
		t.Error(err)
	}
	// Log contains random strings, do a simple sanity check
	if !bytes.Contains(data, []byte("[02/Jan/2006:15:04:20 -0700] 123  0  0")) {
		t.Errorf("failed to match log, \ngot: %s\n", string(data))
	}
}

func createAuditLog() *Log {
	return &Log{
		Parts_: []types.AuditLogPart{
			types.AuditLogPartRequestHeaders,
			types.AuditLogPartRequestBody,
			types.AuditLogPartIntermediaryResponseBody,
			types.AuditLogPartResponseHeaders,
			types.AuditLogPartAuditLogTrailer,
			types.AuditLogPartRulesMatched,
		},
		Transaction_: Transaction{
			Timestamp_:     "02/Jan/2006:15:04:20 -0700",
			UnixTimestamp_: 0,
			ID_:            "123",
			Request_: &TransactionRequest{
				URI_:    "/test.php",
				Method_: "GET",
				Headers_: map[string][]string{
					"some": {
						"somedata",
					},
				},
			},
			Response_: &TransactionResponse{
				Status_: 200,
				Headers_: map[string][]string{
					"some": {
						"somedata",
					},
				},
			},
			Producer_: &TransactionProducer{
				Connector_: "some connector",
				Version_:   "1.2.3",
			},
		},
		Messages_: []plugintypes.AuditLogMessage{
			&Message{
				Message_: "some message",
				Data_: &MessageData{
					Msg_: "some message",
					Raw_: "SecAction \"id:100\"",
				},
			},
		},
	}
}
