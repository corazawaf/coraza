// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package http

import (
	"io"
	"net/http"

	"github.com/corazawaf/coraza/v3/types"
)

// rwInterceptor intercepts the ResponseWriter, so it can track response size
// and returned status code.
type rwInterceptor struct {
	w           http.ResponseWriter
	tx          types.Transaction
	headersSent bool
	proto       string
	respStatus  int
}

func (i *rwInterceptor) WriteHeader(statusCode int) {
	if i.headersSent {
		return
	}

	for k, vv := range i.w.Header() {
		for _, v := range vv {
			i.tx.AddResponseHeader(k, v)
		}
	}

	i.headersSent = true
	if it := i.tx.ProcessResponseHeaders(statusCode, i.proto); it != nil {
		processInterruption(i.w, it)
		return
	}
	i.respStatus = statusCode
	i.w.WriteHeader(statusCode)
}

func (i *rwInterceptor) Write(b []byte) (int, error) {
	return i.tx.ResponseBodyWriter().Write(b)
}

func (i *rwInterceptor) Header() http.Header {
	return i.w.Header()
}

// wrap wraps the interceptor into a response writer that also preserves
// the http interfaces implemented by the original response writer to avoid
// the observer effect.
// Heavily inspired in https://github.com/openzipkin/zipkin-go/blob/master/middleware/http/server.go#L218
func wrap(w http.ResponseWriter, tx types.Transaction) http.ResponseWriter { // nolint:gocyclo
	i := &rwInterceptor{w: w, tx: tx}

	var (
		hijacker, isHijacker = i.w.(http.Hijacker)
		pusher, isPusher     = i.w.(http.Pusher)
		flusher, isFlusher   = i.w.(http.Flusher)
		reader, isReader     = i.w.(io.ReaderFrom)
	)

	i.proto = "HTTP/1.1"
	if isPusher {
		// http.Pusher is only supported in HTTP/2 according to its documentation.
		i.proto = "HTTP/2.0"
	}

	switch {
	case !isHijacker && !isPusher && !isFlusher && !isReader:
		return struct {
			http.ResponseWriter
		}{i}
	case !isHijacker && !isPusher && !isFlusher && isReader:
		return struct {
			http.ResponseWriter
			io.ReaderFrom
		}{i, reader}
	case !isHijacker && !isPusher && isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Flusher
		}{i, flusher}
	case !isHijacker && !isPusher && isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Flusher
			io.ReaderFrom
		}{i, flusher, reader}
	case !isHijacker && isPusher && !isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Pusher
		}{i, pusher}
	case !isHijacker && isPusher && !isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Pusher
			io.ReaderFrom
		}{i, pusher, reader}
	case !isHijacker && isPusher && isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Pusher
			http.Flusher
		}{i, pusher, flusher}
	case !isHijacker && isPusher && isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Pusher
			http.Flusher
			io.ReaderFrom
		}{i, pusher, flusher, reader}
	case isHijacker && !isPusher && !isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
		}{i, hijacker}
	case isHijacker && !isPusher && !isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			io.ReaderFrom
		}{i, hijacker, reader}
	case isHijacker && !isPusher && isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Flusher
		}{i, hijacker, flusher}
	case isHijacker && !isPusher && isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Flusher
			io.ReaderFrom
		}{i, hijacker, flusher, reader}
	case isHijacker && isPusher && !isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
		}{i, hijacker, pusher}
	case isHijacker && isPusher && !isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
			io.ReaderFrom
		}{i, hijacker, pusher, reader}
	case isHijacker && isPusher && isFlusher && !isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
			http.Flusher
		}{i, hijacker, pusher, flusher}
	case isHijacker && isPusher && isFlusher && isReader:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
			http.Flusher
			io.ReaderFrom
		}{i, hijacker, pusher, flusher, reader}
	default:
		return struct {
			http.ResponseWriter
		}{i}
	}
}
