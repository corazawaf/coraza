// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"bytes"
	"testing"
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
		Transaction: Transaction{
			Timestamp:     "02/Jan/2006:15:04:20 -0700",
			UnixTimestamp: 0,
			ID:            "123",
			Request: TransactionRequest{
				URI:    "/test.php",
				Method: "GET",
				Headers: map[string][]string{
					"some": {
						"somedata",
					},
				},
			},
			Response: TransactionResponse{
				Status: 200,
				Headers: map[string][]string{
					"some": {
						"somedata",
					},
				},
			},
		},
		Messages: []Message{
			{
				Message: "some message",
				Data: MessageData{
					Msg: "some message",
					Raw: "SecAction \"id:100\"",
				},
			},
		},
	}
}
