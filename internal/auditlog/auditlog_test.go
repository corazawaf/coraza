// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

import "testing"

func TestAuditLogUnmarshalJSON(t *testing.T) {
	serializedLog := []byte(`{
		"transaction": {
			"id": "abc123"
		},
		"messages": [
			{
				"actionset": "a",
				"message": "b"
			}
		]
	}`)
	log := &Log{}
	if err := log.UnmarshalJSON(serializedLog); err != nil {
		t.Error(err)
	}

	if want, have := "abc123", log.Transaction().ID(); want != have {
		t.Errorf("failed to match transaction id, got: %s, expected: %s", have, want)
	}

	if want, have := false, log.Transaction_.HasRequest(); want != have {
		t.Errorf("failed to match transaction has request, got: %t, expected: %t", have, want)
	}

	if want, have := "", log.Transaction_.Request().Method(); want != have {
		t.Errorf("failed to match transaction request method, got: %s, expected: %s", have, want)
	}

	if want, have := false, log.Transaction_.HasResponse(); want != have {
		t.Errorf("failed to match transaction has response, got: %t, expected: %t", have, want)
	}

	if want, have := 1, len(log.Messages()); want != have {
		t.Errorf("failed to match messages length, got: %d, expected: %d", have, want)
	}

	if want, have := "a", log.Messages()[0].Actionset(); want != have {
		t.Errorf("failed to match actionset, got: %s, expected: %s", have, want)
	}

	if want, have := "b", log.Messages()[0].Message(); want != have {
		t.Errorf("failed to match message, got: %s, expected: %s", have, want)
	}
}
