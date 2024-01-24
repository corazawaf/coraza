// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v4/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v4/types"
)

func checkLine(t *testing.T, lines []string, index int, expected string) {
	t.Helper()
	if lines[index] != expected {
		auditLog := &strings.Builder{}
		auditLog.WriteByte('\n')
		for i, line := range lines {
			auditLog.WriteString(fmt.Sprintf("Line %d: ", i))
			auditLog.WriteString(line)
			auditLog.WriteByte('\n')
		}
		t.Log(auditLog.String())
		t.Fatalf("unexpected line %d, \ngot: %q\nwant: %q\n", index, lines[index], expected)
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

		checkLine(t, lines, 2, "GET /test.php HTTP/1.1")
		checkLine(t, lines, 3, "some: request header")
		checkLine(t, lines, 4, mutateSeparator(separator, 'C'))
		checkLine(t, lines, 6, "some request body")
		checkLine(t, lines, 7, mutateSeparator(separator, 'E'))
		checkLine(t, lines, 9, "some response body")
		checkLine(t, lines, 10, mutateSeparator(separator, 'F'))
		checkLine(t, lines, 12, "some: response header")
		checkLine(t, lines, 13, mutateSeparator(separator, 'H'))
		checkLine(t, lines, 15, "Stopwatch: ")
		checkLine(t, lines, 16, "Response-Body-Transformed: ")
		checkLine(t, lines, 17, "Producer: ")
		checkLine(t, lines, 18, "Server: ")
		checkLine(t, lines, 19, mutateSeparator(separator, 'K'))
		checkLine(t, lines, 21, `SecAction "id:100"`)
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
						"request header",
					},
				},
				Body_:     "some request body",
				Protocol_: "HTTP/1.1",
			},
			Response_: &TransactionResponse{
				Status_: 200,
				Headers_: map[string][]string{
					"some": {
						"response header",
					},
				},
				Body_: "some response body",
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
