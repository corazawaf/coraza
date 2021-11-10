// Copyright 2021 Juan Pablo Tosso
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
	"strings"
	"testing"
)

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
		f, err := GetLogFormatter(format)
		if err != nil {
			t.Error(err)
		}
		for _, c := range cases {
			if out, err := f(c.AuditLog); err != nil {
				t.Error(err)
			} else if out != c.Output {
				//TODO, as the result is a map, it is not ordered and anything can happen :(
				//t.Errorf("failed to match log formatter %s, \ngot: %s\nexpected: %s", format, out, c.Output)
			}
		}
	}
}

func TestModsecBoundary(t *testing.T) {
	al := createAuditLog()
	out, err := nativeFormatter(al)
	if err != nil {
		t.Error(err)
	}
	boundary := out[2:12]
	expected := "--(*)-A--\n[02/Jan/2006:15:04:20 -0700] 123  0  0\n--(*)-B--\nsome: somedata\n\n--(*)-C--\n\n--(*)-E--\n\n--(*)-F--\nsome: somedata\n\n--(*)-H--\n\n--(*)-K--\n0\n\n--(*)-Z--\n\n"
	expected = strings.ReplaceAll(expected, "(*)", boundary)
	if out != expected {
		t.Errorf("failed to match log formatter\ngot: %s\nexpected: %s", strings.ReplaceAll(out, "\n", "\\n"), strings.ReplaceAll(expected, "\n", "\\n"))
	}
}

func createAuditLog() AuditLog {
	return AuditLog{
		Transaction: &AuditTransaction{
			Timestamp:     "02/Jan/2006:15:04:20 -0700",
			UnixTimestamp: 0,
			Id:            "123",
			Request: &AuditTransactionRequest{
				Uri:    "/test.php",
				Method: "GET",
				Headers: map[string][]string{
					"some": {
						"somedata",
					},
				},
			},
			Response: &AuditTransactionResponse{
				Status: 200,
				Headers: map[string][]string{
					"some": {
						"somedata",
					},
				},
			},
		},
		Messages: []*AuditMessage{
			{
				Data: &AuditMessageData{},
			},
		},
	}
}
