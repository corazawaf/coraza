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

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types/variables"
	"github.com/foxcpp/go-mockdns"
	"github.com/stretchr/testify/require"
)

type testLogger struct{ t *testing.T }

func (l *testLogger) Printf(format string, v ...interface{}) {
	l.t.Helper()
	l.t.Logf(format, v...)
}

func TestRbl(t *testing.T) {
	rbl := &rbl{}

	err := rbl.Init("xbl.spamhaus.org")
	require.NoError(t, err, "cannot init rbl operator")

	logger := &testLogger{t}

	srv, _ := mockdns.NewServerWithLogger(map[string]mockdns.Zone{
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
	defer srv.Close()

	srv.PatchNet(rbl.resolver)
	defer mockdns.UnpatchNet(rbl.resolver)

	t.Run("Valid hostname with no TXT record", func(t *testing.T) {
		require.False(t, rbl.Evaluate(nil, "valid_no_txt"), "unexpected result for valid hostname with no TXT record")
	})

	t.Run("Valid hostname with TXT record", func(t *testing.T) {
		tx := coraza.NewWaf().NewTransaction()
		require.True(t, rbl.Evaluate(tx, "valid_txt"), "unexpected result for valid hostname")
		require.Equal(t, "not blocked", tx.GetCollection(variables.TX).Get("httpbl_msg")[0], "unexpected result for valid hostname")
	})

	t.Run("Invalid hostname", func(t *testing.T) {
		require.False(t, rbl.Evaluate(nil, "invalid"), "unexpected result for invalid hostname")
	})

	t.Run("Blocked hostname", func(t *testing.T) {
		tx := coraza.NewWaf().NewTransaction()
		require.True(t, rbl.Evaluate(tx, "blocked"), "unexpected result for blocked hostname")
		t.Log(tx.GetCollection(variables.TX).Get("httpbl_msg"))
		require.Equal(t, "blocked", tx.GetCollection(variables.TX).Get("httpbl_msg")[0], "unexpected result for valid hostname")
	})
}
