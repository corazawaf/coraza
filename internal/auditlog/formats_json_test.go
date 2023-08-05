// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

import (
	"encoding/json"
	"strings"
	"testing"
)

/*
func TestFormatters(t *testing.T) {
	al := createAuditLog()
	type tcase struct {
		Log Log
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
			if out, err := f(c.Log); err != nil {
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
	al := createAuditLog()
	f := &legacyJSONFormatter{}
	data, err := f.Format(al)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(f.MIME(), "json") {
		t.Errorf("failed to match MIME, expected json and got %s", f.MIME())
	}
	var legacyAl logLegacy
	if err := json.Unmarshal(data, &legacyAl); err != nil {
		t.Error(err)
	}
	if legacyAl.Transaction.Time != al.Transaction().Timestamp() {
		t.Errorf("failed to match legacy formatter, \ngot: %s\nexpected: %s", legacyAl.Transaction.Time, al.Transaction().Timestamp())
	}
	// validate transaction ID
	if legacyAl.Transaction.TransactionID != al.Transaction().ID() {
		t.Errorf("failed to match legacy formatter, \ngot: %s\nexpected: %s", legacyAl.Transaction.TransactionID, al.Transaction().ID())
	}
	if legacyAl.AuditData.Messages[0] != "some message" {
		t.Errorf("failed to match legacy formatter, \ngot: %s\nexpected: %s", legacyAl.AuditData.Messages[0], "some message")
	}
}
