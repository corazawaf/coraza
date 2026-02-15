// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package operators

import (
	"testing"

	"github.com/foxcpp/go-mockdns"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err, "Cannot init rbl operator")

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
	require.NoError(t, err, "Cannot start mockdns server")
	defer srv.Close()

	srv.PatchNet(op.(*rbl).resolver)
	defer mockdns.UnpatchNet(op.(*rbl).resolver)

	t.Run("Valid hostname with no TXT record", func(t *testing.T) {
		require.False(t, op.Evaluate(nil, "valid_no_txt"), "Unexpected result for valid hostname with no TXT record")
	})

	t.Run("Valid hostname with TXT record", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		require.True(t, op.Evaluate(tx, "valid_txt"), "Unexpected result for valid hostname")
		require.Equal(t, "not blocked", tx.Variables().TX().Get("httpbl_msg")[0], "Unexpected result for valid hostname")
	})

	t.Run("Invalid hostname", func(t *testing.T) {
		require.False(t, op.Evaluate(nil, "invalid"), "Unexpected result for invalid hostname")
	})

	t.Run("Blocked hostname", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		require.True(t, op.Evaluate(tx, "blocked"), "Unexpected result for blocked hostname")
		t.Log(tx.Variables().TX().Get("httpbl_msg"))
		require.Equal(t, "blocked", tx.Variables().TX().Get("httpbl_msg")[0], "Unexpected result for valid hostname")
	})
}
