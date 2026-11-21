// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Masking itself is rule behaviour and lives in testing/engine/sanitise.go; this
// table only covers argument validation, which never reaches a transaction.
func TestSanitiseInit(t *testing.T) {
	tests := []struct {
		name    string
		action  func() plugintypes.Action
		data    string
		wantErr error
	}{
		{"sanitiseArg with a name", sanitiseArg, "password", nil},
		{"sanitiseArg without a name", sanitiseArg, "", ErrMissingArguments},
		{"sanitiseRequestHeader with a name", sanitiseRequestHeader, "Authorization", nil},
		{"sanitiseRequestHeader without a name", sanitiseRequestHeader, "", ErrMissingArguments},
		{"sanitiseResponseHeader with a name", sanitiseResponseHeader, "Set-Cookie", nil},
		{"sanitiseResponseHeader without a name", sanitiseResponseHeader, "", ErrMissingArguments},
		{"sanitiseMatched without arguments", sanitiseMatched, "", nil},
		{"sanitiseMatched with arguments", sanitiseMatched, "password", ErrUnexpectedArguments},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tt.action()
			if err := a.Init(nil, tt.data); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Init(%q) error = %v, want %v", tt.data, err, tt.wantErr)
			}
			if a.Type() != plugintypes.ActionTypeNondisruptive {
				t.Errorf("Type() = %v, want non-disruptive", a.Type())
			}
		})
	}
}
