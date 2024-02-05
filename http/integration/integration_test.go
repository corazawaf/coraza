// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/negroni/v3"

	coreruleset "github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	coraza_http "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

func Test_WAF_ReverseProxy(t *testing.T) {
	// create the backend server for the proxy to hit. The backend server does some work then responds
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created"))
	}))
	backendURL, err := url.Parse(backend.URL)
	assert.NoError(t, err)

	// create the proxy middleware stack based on negroni with logger first
	m := negroni.New()
	m.Use(negroni.HandlerFunc(func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		nrw := rw.(negroni.ResponseWriter)
		next(nrw, r)
		fmt.Printf("requst: %s, status: %d\n", r.RequestURI, nrw.Status())
	}))

	// add the WAF. Comment out this block and we get the expected resonse codes back
	waf := testWAF(t)
	m.Use(negroni.HandlerFunc(func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		h := coraza_http.WrapHandler(waf, next)
		h.ServeHTTP(rw, r)
	}))

	// point the proxy at the backend. We don't have FlushInterval set to -1 in our proxy but some
	// requests seem to trigger the same behaviour
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	proxy.FlushInterval = -1 // comment out this line and we get the expected status back
	m.UseHandler(proxy)

	// send the request
	rw := httptest.NewRecorder()
	r := testRequest()
	m.ServeHTTP(rw, r)
	assert.Equal(t, http.StatusCreated, rw.Code)
}

func testWAF(t *testing.T) coraza.WAF {
	errorCallBack := func(err types.MatchedRule) {
		msg := err.Message()
		id := err.Rule().ID()
		file := err.Rule().File()
		serverity := err.Rule().Severity().String()
		uri := err.URI()
		data := err.Data()
		fmt.Printf("WAF [%s] %s [%s] ID: %d [%s] URI: %s\n", serverity, msg, data, id, file, uri)
	}

	config := coraza.NewWAFConfig().
		WithErrorCallback(errorCallBack).
		WithRootFS(coreruleset.FS).
		WithDirectives("Include @coraza.conf-recommended").
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives("SecResponseBodyAccess Off").
		WithDirectives("SecRuleEngine On").
		WithDirectives("Include @owasp_crs/*.conf")

	waf, err := coraza.NewWAF(config)
	assert.NoError(t, err)
	return waf
}

func testRequest() *http.Request {
	target := `/foo`
	body := `{"names":["ann", "bob"]}`
	return httptest.NewRequest(http.MethodPost, target, bytes.NewBuffer([]byte(body)))
}
