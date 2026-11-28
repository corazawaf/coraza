// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.disabled_operators.validateSchema

package testing

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/corazawaf/coraza/v3"
)

func TestValidateSchemaSecLangE2E(t *testing.T) {
	root := fstest.MapFS{
		"schemas/req.json": &fstest.MapFile{
			Data: []byte(`{
				"$schema": "https://json-schema.org/draft/2020-12/schema",
				"type": "object",
				"properties": {
					"id": { "type": "integer", "minimum": 1, "maximum": 9007199254740993 },
					"name": { "type": "string", "minLength": 1 }
				},
				"required": ["id", "name"],
				"additionalProperties": false
			}`),
			Mode: 0o644,
		},
		"schemas/resp.json": &fstest.MapFile{
			Data: []byte(`{
				"type": "object",
				"properties": {
					"status": { "enum": ["ok", "queued"] }
				},
				"required": ["status"],
				"additionalProperties": false
			}`),
			Mode: 0o644,
		},
	}

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(root).
		WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecResponseBodyAccess On
			SecResponseBodyMimeType application/json
			SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:100,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
			SecRule RESPONSE_HEADERS:Content-Type "^application/json" "id:103,phase:3,pass,nolog,ctl:responseBodyProcessor=JSON"
			SecRule REQUEST_BODY "@validateSchema schemas/req.json" "id:101,phase:2,deny,status:400,nolog"
			SecRule RESPONSE_BODY "@validateSchema schemas/resp.json" "id:102,phase:4,deny,status:502,nolog"
		`))
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	runTx := func(t *testing.T, reqBody, respBody string) (reqStatus, respStatus, reqRule, respRule int) {
		tx := waf.NewTransaction()
		defer func() {
			tx.ProcessLogging()
			if err := tx.Close(); err != nil {
				t.Errorf("close transaction: %v", err)
			}
		}()
		tx.ProcessConnection("127.0.0.1", 12345, "127.0.0.1", 8080)
		tx.ProcessURI("/api/item", "POST", "HTTP/1.1")
		tx.AddRequestHeader("Host", "example.test")
		tx.AddRequestHeader("Content-Type", "application/json")
		if it := tx.ProcessRequestHeaders(); it != nil {
			return it.Status, 0, it.RuleID, 0
		}
		if _, _, err := tx.ReadRequestBodyFrom(strings.NewReader(reqBody)); err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if it, err := tx.ProcessRequestBody(); err != nil {
			t.Fatalf("process request body: %v", err)
		} else if it != nil {
			return it.Status, 0, it.RuleID, 0
		}
		tx.AddResponseHeader("Content-Type", "application/json")
		if it := tx.ProcessResponseHeaders(200, "HTTP/1.1"); it != nil {
			return 0, it.Status, 0, it.RuleID
		}
		if _, _, err := tx.ReadResponseBodyFrom(strings.NewReader(respBody)); err != nil {
			t.Fatalf("read response body: %v", err)
		}
		if it, err := tx.ProcessResponseBody(); err != nil {
			t.Fatalf("process response body: %v", err)
		} else if it != nil {
			return 0, it.Status, 0, it.RuleID
		}
		return 0, 0, 0, 0
	}

	t.Run("valid request and response pass", func(t *testing.T) {
		rs, ps, _, _ := runTx(t, `{"id":9007199254740993,"name":"alice"}`, `{"status":"ok"}`)
		if rs != 0 || ps != 0 {
			t.Fatalf("expected allow, got reqStatus=%d respStatus=%d", rs, ps)
		}
	})

	t.Run("invalid request blocked at phase 2", func(t *testing.T) {
		rs, _, rr, _ := runTx(t, `{"id":1,"name":"alice","extra":true}`, `{"status":"ok"}`)
		if rs != 400 || rr != 101 {
			t.Fatalf("expected status 400 rule 101, got status=%d rule=%d", rs, rr)
		}
	})

	t.Run("oversized exponent request blocked cleanly without panic", func(t *testing.T) {
		rs, _, rr, _ := runTx(t, `{"id":1e9999999999,"name":"alice"}`, `{"status":"ok"}`)
		if rs != 400 || rr != 101 {
			t.Fatalf("expected status 400 rule 101, got status=%d rule=%d", rs, rr)
		}
	})

	t.Run("invalid response blocked at phase 4", func(t *testing.T) {
		_, ps, _, pr := runTx(t, `{"id":42,"name":"alice"}`, `{"status":"bad"}`)
		if ps != 502 || pr != 102 {
			t.Fatalf("expected status 502 rule 102, got status=%d rule=%d", ps, pr)
		}
	})
}
