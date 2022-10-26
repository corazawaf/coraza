// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package http

import (
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// processRequest fills all transaction variables from an http.Request object
// Most implementations of Coraza will probably use http.Request objects
// so this will implement all phase 0, 1 and 2 variables
// Note: This function will stop after an interruption
// Note: Do not manually fill any request variables
func processRequest(tx types.Transaction, req *http.Request) (*types.Interruption, error) {
	var (
		client string
		cport  int
	)
	// IMPORTANT: Some http.Request.RemoteAddr implementations will not contain port or contain IPV6: [2001:db8::1]:8080
	idx := strings.LastIndexByte(req.RemoteAddr, ':')
	if idx != -1 {
		client = req.RemoteAddr[:idx]
		cport, _ = strconv.Atoi(req.RemoteAddr[idx+1:])
	}

	var in *types.Interruption
	// There is no socket access in the request object, so we neither know the server client nor port.
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)
	for k, vr := range req.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}
	// Host will always be removed from req.Headers(), so we manually add it
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
	}

	in = tx.ProcessRequestHeaders()
	if in != nil {
		return in, nil
	}
	if req.Body != nil {
		_, err := io.Copy(tx.RequestBodyWriter(), req.Body)
		if err != nil {
			return tx.GetInterruption(), err
		}
		reader, err := tx.RequestBodyReader()
		if err != nil {
			return tx.GetInterruption(), err
		}
		req.Body = io.NopCloser(reader)
	}

	return tx.ProcessRequestBody()
}

func WrapHandler(waf coraza.WAF, l Logger, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction()
		defer func() {
			// We run phase 5 rules and create audit logs (if enabled)
			tx.ProcessLogging()
			// we remove temporary files and free some memory
			if err := tx.Close(); err != nil {
				l("failed to close the transaction: %v", err)
			}
		}()

		// ProcessRequest is just a wrapper around ProcessConnection, ProcessURI,
		// ProcessRequestHeaders and ProcessRequestBody.
		// It fails if any of these functions returns an error and it stops on interruption.
		if it, err := processRequest(tx, r); err != nil {
			l("failed to process request: %v", err)
			return
		} else if it != nil {
			processInterruption(w, it)
			return
		}

		ww := wrap(w, tx)

		// We continue with the other middlewares by catching the response
		h.ServeHTTP(ww, r)

		for k, vv := range w.Header() {
			for _, v := range vv {
				tx.AddResponseHeader(k, v)
			}
		}

		if it := tx.ProcessResponseHeaders(ww.StatusCode(), r.Proto); it != nil {
			processInterruption(w, it)
			return
		}

		if it, err := tx.ProcessResponseBody(); err != nil {
			l("failed to process response body: %v", err)
			return
		} else if it != nil {
			processInterruption(w, it)
			return
		}

		// we release the buffer
		reader, err := tx.ResponseBodyReader()
		if err != nil {
			l("failed to release the response body reader: %v", err)
			w.WriteHeader(500)
			return
		}

		statusCode := ww.StatusCode()
		if statusCode == 0 {
			// If WriteHeader has not yet been called, Write calls
			// WriteHeader(http.StatusOK) before writing the data
			statusCode = http.StatusOK
		}
		// Interceptor never calls the WritHeader, hence we call it here reusing
		// intercepted status code.
		w.WriteHeader(statusCode)
		if _, err := io.Copy(w, reader); err != nil {
			l("failed to copy the response body: %v", err)
		}
	}

	return http.HandlerFunc(fn)
}

func processInterruption(w http.ResponseWriter, it *types.Interruption) {
	if it.Status == 0 {
		it.Status = 503
	}

	if it.Action == "deny" {
		w.WriteHeader(it.Status)
	}
}
