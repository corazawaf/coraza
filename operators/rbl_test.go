// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package operators

import (
	"context"
	"testing"

	"github.com/foxcpp/go-mockdns"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

type testLogger struct{ t *testing.T }

func (l *testLogger) Printf(format string, v ...interface{}) {
	l.t.Helper()
	l.t.Logf(format, v...)
}

func TestRbl(t *testing.T) {
	rbl := &rbl{}
	opts := rules.OperatorOptions{
		Arguments: "xbl.spamhaus.org",
	}
	if err := rbl.Init(opts); err != nil {
		t.Error("Cannot init rbl operator")
	}

	logger := &testLogger{t}

	srv, err := mockdns.NewServerWithLogger(map[string]mockdns.Zone{
		"valid_no_txt.xbl.spamhaus.org.": {
			A: []string{"1.2.3.4"},
		},
		"valid_txt.xbl.spamhaus.org.": {
			A:   []string{"1.2.3.5"},
			TXT: []string{"not blocked"},
		},
		"blocked.xbl.spamhaus.org.": {
			A:   []string{"1.2.3.6"},
			TXT: []string{"blocked"},
		},
	}, logger, false)
	if err != nil {
		t.Error("Cannot start mockdns server")
	}
	defer srv.Close()

	srv.PatchNet(rbl.resolver)
	defer mockdns.UnpatchNet(rbl.resolver)

	t.Run("Valid hostname with no TXT record", func(t *testing.T) {
		if rbl.Evaluate(nil, "valid_no_txt") {
			t.Errorf("Unexpected result for valid hostname with no TXT record")
		}
	})

	t.Run("Valid hostname with TXT record", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction(context.Background())
		if !rbl.Evaluate(tx, "valid_txt") {
			t.Errorf("Unexpected result for valid hostname")
		}
		if want, have := "not blocked", tx.Variables.TX.Get("httpbl_msg")[0]; want != have {
			t.Errorf("Unexpected result for valid hostname: want %q, have %q", want, have)
		}
	})

	t.Run("Invalid hostname", func(t *testing.T) {
		if rbl.Evaluate(nil, "invalid") {
			t.Errorf("Unexpected result for invalid hostname")
		}
	})

	t.Run("Blocked hostname", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction(context.Background())
		if !rbl.Evaluate(tx, "blocked") {
			t.Fatal("Unexpected result for blocked hostname")
		}
		t.Log(tx.Variables.TX.Get("httpbl_msg"))
		if want, have := "blocked", tx.Variables.TX.Get("httpbl_msg")[0]; want != have {
			t.Errorf("Unexpected result for valid hostname: want %q, have %q", want, have)
		}
	})
}
