// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package http

import (
	"fmt"
	"io"
	"net/http"

	"github.com/corazawaf/coraza/v3/types"
)

// rwInterceptor intercepts the ResponseWriter, so it can track response size
// and returned status code.
type rwInterceptor struct {
	w             http.ResponseWriter
	tx            types.Transaction
	statusCode    int
	proto         string
	hasStatusCode bool
}

func (i *rwInterceptor) WriteHeader(statusCode int) {
	if i.hasStatusCode {
		return
	}

	for k, vv := range i.w.Header() {
		for _, v := range vv {
			i.tx.AddResponseHeader(k, v)
		}
	}

	i.hasStatusCode = true
	i.statusCode = statusCode
	if it := i.tx.ProcessResponseHeaders(statusCode, i.proto); it != nil {
		i.statusCode = obtainStatusCodeFromInterruptionOrDefault(it, i.statusCode)
	}
}

func (i *rwInterceptor) Write(b []byte) (int, error) {
	if !i.hasStatusCode {
		i.WriteHeader(http.StatusOK)
	}

	if i.tx.Interrupted() {
		// if there is an interruption it must be from phase 4 and hence
		// we won't write anything to either the body or the buffer.
		return 0, nil
	}

	if i.tx.ResponseBodyAccessible() {
		// we only buffer the response body if we are going to access
		// to it, otherwise we just send it to the response writer.
		return i.tx.ResponseBodyWriter().Write(b)
	}

	return i.w.Write(b)
}

func (i *rwInterceptor) Header() http.Header {
	return i.w.Header()
}

var _ http.ResponseWriter = (*rwInterceptor)(nil)

// wrap wraps the interceptor into a response writer that also preserves
// the http interfaces implemented by the original response writer to avoid
// the observer effect. It also returns the response processor which takes care
// of the response body copyback from the transaction buffer.
//
// Heavily inspired in https://github.com/openzipkin/zipkin-go/blob/master/middleware/http/server.go#L218
func wrap(w http.ResponseWriter, r *http.Request, tx types.Transaction) (
	http.ResponseWriter,
	func(types.Transaction, *http.Request) error,
) { // nolint:gocyclo

	i := &rwInterceptor{w: w, tx: tx, proto: r.Proto}

	responseProcessor := func(tx types.Transaction, r *http.Request) error {
		// We look for interruptions determined at phase 4 (response headers)
		// as body hasn't being analized yet.
		if tx.Interrupted() {
			// phase 4 interruption stops execution
			w.WriteHeader(i.statusCode)
			return nil
		}

		if tx.ResponseBodyAccessible() && tx.IsProcessableResponseBody() {
			if it, err := tx.ProcessResponseBody(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return err
			} else if it != nil {
				w.WriteHeader(obtainStatusCodeFromInterruptionOrDefault(it, i.statusCode))
				return nil
			}

			// we release the buffer
			reader, err := tx.ResponseBodyReader()
			if err != nil {
				i.w.WriteHeader(http.StatusInternalServerError)
				return fmt.Errorf("failed to release the response body reader: %v", err)
			}

			// this is the last opportunity we have to report the resolved status code
			// as next step is write into the response writer (triggering a 200 in the
			// response status code.)
			i.w.WriteHeader(i.statusCode)
			if _, err := io.Copy(w, reader); err != nil {
				i.w.WriteHeader(http.StatusInternalServerError)
				return fmt.Errorf("failed to copy the response body: %v", err)
			}
		} else {
			i.w.WriteHeader(i.statusCode)
		}

		return nil
	}

	var (
		hijacker, isHijacker = i.w.(http.Hijacker)
		pusher, isPusher     = i.w.(http.Pusher)
		flusher, isFlusher   = i.w.(http.Flusher)
		reader, isReader     = i.w.(io.ReaderFrom)
	)

	switch {
	case !isHijacker && !isPusher && !isFlusher && !isReader:
		return struct {
			http.ResponseWriter
		}{i}, responseProcessor
	case !isHijacker && !isPusher && !isFlusher && isReader:
		return struct {
			http.ResponseWriter
			io.ReaderFrom
		}{i, reader}, responseProcessor
	case !isHijacker && !isPusher && isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Flusher
		}{i, flusher}, responseProcessor
	case !isHijacker && !isPusher && isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Flusher
			io.ReaderFrom
		}{i, flusher, reader}, responseProcessor
	case !isHijacker && isPusher && !isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Pusher
		}{i, pusher}, responseProcessor
	case !isHijacker && isPusher && !isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Pusher
			io.ReaderFrom
		}{i, pusher, reader}, responseProcessor
	case !isHijacker && isPusher && isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Pusher
			http.Flusher
		}{i, pusher, flusher}, responseProcessor
	case !isHijacker && isPusher && isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Pusher
			http.Flusher
			io.ReaderFrom
		}{i, pusher, flusher, reader}, responseProcessor
	case isHijacker && !isPusher && !isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
		}{i, hijacker}, responseProcessor
	case isHijacker && !isPusher && !isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			io.ReaderFrom
		}{i, hijacker, reader}, responseProcessor
	case isHijacker && !isPusher && isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Flusher
		}{i, hijacker, flusher}, responseProcessor
	case isHijacker && !isPusher && isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Flusher
			io.ReaderFrom
		}{i, hijacker, flusher, reader}, responseProcessor
	case isHijacker && isPusher && !isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
		}{i, hijacker, pusher}, responseProcessor
	case isHijacker && isPusher && !isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
			io.ReaderFrom
		}{i, hijacker, pusher, reader}, responseProcessor
	case isHijacker && isPusher && isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
			http.Flusher
		}{i, hijacker, pusher, flusher}, responseProcessor
	case isHijacker && isPusher && isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
			http.Flusher
			io.ReaderFrom
		}{i, hijacker, pusher, flusher, reader}, responseProcessor
	default:
		return struct {
			http.ResponseWriter
		}{i}, responseProcessor
	}
}
