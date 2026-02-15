// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"strings"
	"testing"

	_ "github.com/corazawaf/coraza/v3/experimental/bodyprocessors"
)

func TestStreamingPerRecordEvaluation(t *testing.T) {
	// WAF with a Phase 1 rule to set the body processor and a Phase 2 rule
	// that matches on ARGS_POST content.
	waf, err := NewWAF(NewWAFConfig().WithDirectives(`
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule REQUEST_HEADERS:content-type "application/x-ndjson" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSONSTREAM"
		SecRule ARGS_POST "@contains evil" "id:100,phase:2,deny,status:403,msg:'Evil detected'"
	`))
	if err != nil {
		t.Fatalf("failed to create WAF: %v", err)
	}

	t.Run("interruption stops at bad record", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		tx.ProcessConnection("127.0.0.1", 1234, "", 0)
		tx.ProcessURI("/test", "POST", "HTTP/1.1")
		tx.AddRequestHeader("Content-Type", "application/x-ndjson")
		tx.AddRequestHeader("Host", "example.com")

		if it := tx.ProcessRequestHeaders(); it != nil {
			t.Fatalf("unexpected interruption at headers: %v", it)
		}

		// 5 records, record 2 (index 2) contains "evil"
		body := `{"name": "Alice"}
{"name": "Bob"}
{"name": "evil payload"}
{"name": "Charlie"}
{"name": "Dave"}
`
		if it, _, err := tx.ReadRequestBodyFrom(strings.NewReader(body)); err != nil {
			t.Fatalf("failed to write request body: %v", err)
		} else if it != nil {
			t.Fatalf("unexpected interruption writing body: %v", it)
		}

		it, err := tx.ProcessRequestBody()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if it == nil {
			t.Fatal("expected interruption from evil record, got nil")
		}
		if it.Status != 403 {
			t.Errorf("expected status 403, got %d", it.Status)
		}

		// Verify that rule 100 was matched
		matched := tx.MatchedRules()
		found := false
		for _, mr := range matched {
			if mr.Rule().ID() == 100 {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected rule 100 to be in matched rules")
		}
	})

	t.Run("clean records pass through", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		tx.ProcessConnection("127.0.0.1", 1234, "", 0)
		tx.ProcessURI("/test", "POST", "HTTP/1.1")
		tx.AddRequestHeader("Content-Type", "application/x-ndjson")
		tx.AddRequestHeader("Host", "example.com")

		if it := tx.ProcessRequestHeaders(); it != nil {
			t.Fatalf("unexpected interruption at headers: %v", it)
		}

		// All records are clean
		body := `{"name": "Alice"}
{"name": "Bob"}
{"name": "Charlie"}
`
		if it, _, err := tx.ReadRequestBodyFrom(strings.NewReader(body)); err != nil {
			t.Fatalf("failed to write request body: %v", err)
		} else if it != nil {
			t.Fatalf("unexpected interruption writing body: %v", it)
		}

		it, err := tx.ProcessRequestBody()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if it != nil {
			t.Fatalf("unexpected interruption for clean records: %v", it)
		}
	})
}

func TestStreamingTXVariablesPersistAcrossRecords(t *testing.T) {
	// WAF that increments a TX variable for each record using setvar.
	// After processing 3 records, tx.score should be 3.
	// A rule checks if tx.score >= 3 and blocks.
	waf, err := NewWAF(NewWAFConfig().WithDirectives(`
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule REQUEST_HEADERS:content-type "application/x-ndjson" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSONSTREAM"
		SecRule ARGS_POST "@rx .*" "id:100,phase:2,pass,nolog,setvar:tx.score=+1"
		SecRule TX:score "@ge 3" "id:200,phase:2,deny,status:403,msg:'Score threshold reached'"
	`))
	if err != nil {
		t.Fatalf("failed to create WAF: %v", err)
	}

	t.Run("TX variables accumulate across records", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		tx.ProcessConnection("127.0.0.1", 1234, "", 0)
		tx.ProcessURI("/test", "POST", "HTTP/1.1")
		tx.AddRequestHeader("Content-Type", "application/x-ndjson")
		tx.AddRequestHeader("Host", "example.com")

		if it := tx.ProcessRequestHeaders(); it != nil {
			t.Fatalf("unexpected interruption at headers: %v", it)
		}

		// 3 records - each increments tx.score by 1
		// After record 2 (3rd record), tx.score should reach 3 and trigger rule 200
		body := `{"data": "a"}
{"data": "b"}
{"data": "c"}
`
		if it, _, err := tx.ReadRequestBodyFrom(strings.NewReader(body)); err != nil {
			t.Fatalf("failed to write request body: %v", err)
		} else if it != nil {
			t.Fatalf("unexpected interruption writing body: %v", it)
		}

		it, err := tx.ProcessRequestBody()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if it == nil {
			t.Fatal("expected interruption from score threshold, got nil")
		}
		if it.Status != 403 {
			t.Errorf("expected status 403, got %d", it.Status)
		}

		// Verify that rule 200 was matched (score threshold)
		matched := tx.MatchedRules()
		found := false
		for _, mr := range matched {
			if mr.Rule().ID() == 200 {
				found = true
				break
			}
		}
		if !found {
			ids := make([]int, 0, len(matched))
			for _, mr := range matched {
				ids = append(ids, mr.Rule().ID())
			}
			t.Errorf("expected rule 200 to be in matched rules, got: %v", ids)
		}
	})

	t.Run("fewer records dont trigger threshold", func(t *testing.T) {
		tx := waf.NewTransaction()
		defer tx.Close()

		tx.ProcessConnection("127.0.0.1", 1234, "", 0)
		tx.ProcessURI("/test", "POST", "HTTP/1.1")
		tx.AddRequestHeader("Content-Type", "application/x-ndjson")
		tx.AddRequestHeader("Host", "example.com")

		if it := tx.ProcessRequestHeaders(); it != nil {
			t.Fatalf("unexpected interruption at headers: %v", it)
		}

		// Only 2 records - tx.score reaches 2, below threshold of 3
		body := `{"data": "a"}
{"data": "b"}
`
		if it, _, err := tx.ReadRequestBodyFrom(strings.NewReader(body)); err != nil {
			t.Fatalf("failed to write request body: %v", err)
		} else if it != nil {
			t.Fatalf("unexpected interruption writing body: %v", it)
		}

		it, err := tx.ProcessRequestBody()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if it != nil {
			t.Fatalf("unexpected interruption for 2 records (below threshold): %v", it)
		}
	})
}
