// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package operators

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/foxcpp/go-mockdns"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type testLogger struct{ t *testing.T }

func (l *testLogger) Printf(format string, v ...any) {
	l.t.Helper()
	l.t.Logf(format, v...)
}

func TestRbl(t *testing.T) {
	opts := plugintypes.OperatorOptions{
		Arguments: "xbl.spamhaus.org",
	}
	op, err := newRBL(opts)
	if err != nil {
		t.Fatal("Cannot init rbl operator")
	}

	logger := &testLogger{t}

	// IPv4 inputs are queried with their octets reversed, as DNSBLs expect:
	// 10.0.0.1 -> 1.0.0.10.xbl.spamhaus.org.
	srv, err := mockdns.NewServerWithLogger(map[string]mockdns.Zone{
		"1.0.0.10.xbl.spamhaus.org.": {
			A: []string{"1.2.3.4"},
		},
		"2.0.0.10.xbl.spamhaus.org.": {
			A:   []string{"1.2.3.5"},
			TXT: []string{"not blocked"},
		},
		"3.0.0.10.xbl.spamhaus.org.": {
			A:   []string{"1.2.3.6"},
			TXT: []string{"blocked"},
		},
		"domain-format.xbl.spamhaus.org.": {
			A:   []string{"1.2.3.7"},
			TXT: []string{"blocked"},
		},
	}, logger, false)
	if err != nil {
		t.Fatalf("Cannot start mockdns server: %v", err)
	}
	defer srv.Close()

	srv.PatchNet(op.(*rbl).resolver)
	defer mockdns.UnpatchNet(op.(*rbl).resolver)

	t.Run("Listed IP with no TXT record", func(t *testing.T) {
		if op.Evaluate(nil, "10.0.0.1") {
			t.Errorf("Unexpected result for listed IP with no TXT record")
		}
	})

	t.Run("Listed IP with TXT record", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		if !op.Evaluate(tx, "10.0.0.2") {
			t.Errorf("Unexpected result for listed IP")
		}
		if want, have := "not blocked", tx.Variables().TX().Get("httpbl_msg")[0]; want != have {
			t.Errorf("Unexpected result for listed IP: want %q, have %q", want, have)
		}
	})

	t.Run("Unlisted IP", func(t *testing.T) {
		if op.Evaluate(nil, "10.0.0.9") {
			t.Errorf("Unexpected result for unlisted IP")
		}
	})

	t.Run("Unreversed IP is not found", func(t *testing.T) {
		if op.Evaluate(nil, "1.0.0.10") {
			t.Errorf("Unexpected result: the query must reverse the octets")
		}
	})

	t.Run("Domain format input is used as is", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		if !op.Evaluate(tx, "domain-format") {
			t.Errorf("Unexpected result for domain format input")
		}
	})

	t.Run("Blocked IP", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		if !op.Evaluate(tx, "10.0.0.3") {
			t.Fatal("Unexpected result for blocked IP")
		}
		if want, have := "blocked", tx.Variables().TX().Get("httpbl_msg")[0]; want != have {
			t.Errorf("Unexpected result for blocked IP: want %q, have %q", want, have)
		}
	})

	// Not a table row: the behaviour under test is that the lookup goroutine
	// exits after a timeout, which needs a goroutine count, not an output.
	// Uses its own resolver, blocked until the context ends, so the timed-out
	// lookup never touches the mockdns server torn down by the parent test.
	t.Run("Timeout does not leak the lookup goroutine", func(t *testing.T) {
		slow := &rbl{
			service: "xbl.spamhaus.org",
			timeout: time.Millisecond,
			resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				},
			},
		}

		before := runtime.NumGoroutine()
		if slow.Evaluate(nil, "10.0.0.3") {
			t.Fatal("Expected the lookup to time out")
		}
		deadline := time.Now().Add(2 * time.Second)
		for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if after := runtime.NumGoroutine(); after > before {
			t.Fatalf("lookup goroutine leaked: %d goroutines before, %d after", before, after)
		}
	})
}
