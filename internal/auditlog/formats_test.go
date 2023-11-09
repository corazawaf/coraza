// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

func checkLine(t *testing.T, line, expected string) {
	t.Helper()
	if line != expected {
		t.Errorf("unexpected line, \ngot: %q\nwant: %q\n", line, expected)
	}
}

func mutateSeparator(separator string, part byte) string {
	return separator[:len(separator)-3] + string(part) + separator[len(separator)-2:]
}

func TestNativeFormatter(t *testing.T) {
	f := &nativeFormatter{}

	t.Run("empty parts", func(t *testing.T) {
		al := &Log{}
		l, err := f.Format(al)
		if l != nil {
			t.Error("expected nil log")
		}
		if err != nil {
			t.Error("unexpected error")
		}
	})

	t.Run("success", func(t *testing.T) {
		al := createAuditLog()
		data, err := f.Format(al)
		if err != nil {
			t.Error(err)
		}
		if !strings.Contains(f.MIME(), "x-coraza-auditlog-native") {
			t.Errorf("failed to match MIME, expected json and got %s", f.MIME())
		}
		// Log contains random strings, do a simple sanity check
		if !bytes.Contains(data, []byte("[02/Jan/2006:15:04:20 -0700] 123  0  0")) {
			t.Errorf("failed to match log, \ngot: %s\n", string(data))
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))

		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		separator := lines[0]

		checkLine(t, lines[2], "GET /test.php HTTP/1.1")
		checkLine(t, lines[3], "some: somedata")
		checkLine(t, lines[4], mutateSeparator(separator, 'C'))
		checkLine(t, lines[6], mutateSeparator(separator, 'E'))
		checkLine(t, lines[8], mutateSeparator(separator, 'F'))
		checkLine(t, lines[10], "some: somedata")
		checkLine(t, lines[11], mutateSeparator(separator, 'H'))
		checkLine(t, lines[13], "Stopwatch: ")
		checkLine(t, lines[14], "Response-Body-Transformed: ")
		checkLine(t, lines[15], "Producer: ")
		checkLine(t, lines[16], "Server: ")
		checkLine(t, lines[17], mutateSeparator(separator, 'K'))
		checkLine(t, lines[19], `SecAction "id:100"`)
	})
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
				Protocol_: "HTTP/1.1",
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
