// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestWriteHeader(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
		# This is a comment
		SecResponseBodyAccess Off
		SecResponseBodyMimeType text/plain
		SecRule RESPONSE_BODY "@contains password" "id:200, phase:4,deny, status:403,msg:'Invalid response body',log,auditlog"
	`).WithErrorLogger(errLogger(t)).WithDebugLogger(&debugLogger{t: t}))
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()
	rw, rp := wrap(res, req, tx)
	rw.WriteHeader(204)
	if unwanted, have := 204, res.Code; unwanted == have {
		t.Errorf("unexpected status code %d", have)
	}

	err = rp(tx, req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if want, have := 204, res.Code; want != have {
		t.Errorf("unexpected status code, want %d, have %d", want, have)
	}
}
