// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loggers

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

/*
func TestFormatters(t *testing.T) {
	al := createAuditLog()
	type tcase struct {
		AuditLog AuditLog
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
			if out, err := f(c.AuditLog); err != nil {
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
	al := createAuditLog(t)
	data, err := legacyJSONFormatter(al)
	require.NoError(t, err)

	var legacyAl auditLogLegacy
	err = json.Unmarshal(data, &legacyAl)
	require.NoError(t, err)
	require.Equal(t, legacyAl.Transaction.Time, al.Transaction.Timestamp, "failed to match legacy formatter")

	// validate transaction ID
	require.Equal(t, legacyAl.Transaction.TransactionID, al.Transaction.ID, "failed to match legacy formatter")

	require.Equal(t, "some message", legacyAl.AuditData.Messages[0], "failed to match legacy formatter")
}

func createAuditLog(t *testing.T) *AuditLog {
	t.Helper()
	return &AuditLog{
		Transaction: AuditTransaction{
			Timestamp:     "02/Jan/2006:15:04:20 -0700",
			UnixTimestamp: 0,
			ID:            "123",
			Request: AuditTransactionRequest{
				URI:    "/test.php",
				Method: "GET",
				Headers: map[string][]string{
					"some": {
						"somedata",
					},
				},
			},
			Response: AuditTransactionResponse{
				Status: 200,
				Headers: map[string][]string{
					"some": {
						"somedata",
					},
				},
			},
		},
		Messages: []AuditMessage{
			{
				Message: "some message",
				Data: AuditMessageData{
					Msg: "some message",
					Raw: "SecAction \"id:100\"",
				},
			},
		},
	}
}
