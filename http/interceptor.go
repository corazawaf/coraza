// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Channels and goroutines are not going to work with tinygo
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

// Heavily inspired in https://github.com/openzipkin/zipkin-go/blob/master/middleware/http/server.go#L218
func (r *rwInterceptor) wrap() http.ResponseWriter { // nolint:gocyclo
	var (
		hj, i0 = r.w.(http.Hijacker)
		pu, i2 = r.w.(http.Pusher)
		fl, i3 = r.w.(http.Flusher)
		rf, i4 = r.w.(io.ReaderFrom)
	)

	r.proto = "HTTP/1.1"
	if i2 {
		r.proto = "HTTP/2.0"
	}

	switch {
	case !i0 && !i2 && !i3 && !i4:
		return struct {
			http.ResponseWriter
		}{r}
	case !i0 && !i2 && !i3 && i4:
		return struct {
			http.ResponseWriter
			io.ReaderFrom
		}{r, rf}
	case !i0 && !i2 && i3 && !i4:
		return struct {
			http.ResponseWriter
			http.Flusher
		}{r, fl}
	case !i0 && !i2 && i3 && i4:
		return struct {
			http.ResponseWriter
			http.Flusher
			io.ReaderFrom
		}{r, fl, rf}
	case !i0 && i2 && !i3 && !i4:
		return struct {
			http.ResponseWriter
			http.Pusher
		}{r, pu}
	case !i0 && i2 && !i3 && i4:
		return struct {
			http.ResponseWriter
			http.Pusher
			io.ReaderFrom
		}{r, pu, rf}
	case !i0 && i2 && i3 && !i4:
		return struct {
			http.ResponseWriter
			http.Pusher
			http.Flusher
		}{r, pu, fl}
	case !i0 && i2 && i3 && i4:
		return struct {
			http.ResponseWriter
			http.Pusher
			http.Flusher
			io.ReaderFrom
		}{r, pu, fl, rf}
	case i0 && !i2 && !i3 && !i4:
		return struct {
			http.ResponseWriter
			http.Hijacker
		}{r, hj}
	case i0 && !i2 && !i3 && i4:
		return struct {
			http.ResponseWriter
			http.Hijacker
			io.ReaderFrom
		}{r, hj, rf}
	case i0 && !i2 && i3 && !i4:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Flusher
		}{r, hj, fl}
	case i0 && !i2 && i3 && i4:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Flusher
			io.ReaderFrom
		}{r, hj, fl, rf}
	case i0 && i2 && !i3 && !i4:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
		}{r, hj, pu}
	case i0 && i2 && !i3 && i4:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
			io.ReaderFrom
		}{r, hj, pu, rf}
	case i0 && i2 && i3 && !i4:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
			http.Flusher
		}{r, hj, pu, fl}
	case i0 && i2 && i3 && i4:
		return struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
			http.Flusher
			io.ReaderFrom
		}{r, hj, pu, fl, rf}
	default:
		return struct {
			http.ResponseWriter
		}{r}
	}
}
