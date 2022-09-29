// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Channels and goroutines are not going to work with tinygo
//go:build !tinygo
// +build !tinygo

package http

import (
	"context"
	"io"
	"net/http"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

func WrapHandler(waf coraza.WAF, l Logger, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction(context.Background())
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
			h.ServeHTTP(w, r)
			return
		} else if it != nil {
			processInterruption(w, it)
			return
		}

		ri := &rwInterceptor{
			w:  w,
			tx: tx,
		}

		// We continue with the other middlewares by catching the response
		h.ServeHTTP(ri.wrap(), r)

		it := tx.ProcessResponseHeaders(200, "HTTP/2.0")
		if it != nil {
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

		if _, err := io.Copy(w, reader); err != nil {
			l("failed to copy the response body: %v", err)
			w.WriteHeader(500)
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
