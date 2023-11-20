// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package http

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestWriteHeader(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()
	rw, responseProcessor := wrap(res, req, tx)
	rw.WriteHeader(204)
	rw.WriteHeader(205)
	// although we called WriteHeader, status code should be applied until
	// responseProcessor is called.
	if unwanted, have := 204, res.Code; unwanted == have {
		t.Errorf("unexpected status code %d", have)
	}

	err = responseProcessor(tx, req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// although we called a second time with 205, status code should remain the first
	// value.
	if want, have := 204, res.Code; want != have {
		t.Errorf("unexpected status code, want %d, have %d", want, have)
	}
}

func TestFlush(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()
	rw, responseProcessor := wrap(res, req, tx)
	rw.WriteHeader(204)
	rw.(http.Flusher).Flush()
	// although we called WriteHeader, status code should be applied until
	// responseProcessor is called.
	if unwanted, have := 204, res.Code; unwanted == have {
		t.Errorf("unexpected status code %d", have)
	}

	err = responseProcessor(tx, req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if want, have := 204, res.Code; want != have {
		t.Errorf("unexpected status code, want %d, have %d", want, have)
	}
}

func TestReadFrom(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()
	rw, _ := wrap(res, req, tx)
	rw.WriteHeader(204)
	_, err = rw.(io.ReaderFrom).ReadFrom(bytes.NewBuffer([]byte("hello world")))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if want, have := 204, res.Code; want != have {
		t.Errorf("unexpected status code, want %d, have %d", want, have)
	}
}
