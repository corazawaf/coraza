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

	"github.com/corazawaf/coraza/v3/types"
)

// rwInterceptor intercepts the ResponseWriter, so it can track response size
// and returned status code.
type rwInterceptor struct {
	w           http.ResponseWriter
	tx          types.Transaction
	headersSent bool
	proto       string
}

func (i *rwInterceptor) WriteHeader(statusCode int) {
	if i.headersSent {
		return
	}
	i.w.WriteHeader(statusCode)
}

func (i *rwInterceptor) Write(b []byte) (int, error) {
	// Echoing the body request
	buf := new(bytes.Buffer)
	reqReader, err := i.tx.RequestBodyReader()
	if err == nil {
		_, er := buf.ReadFrom(reqReader)
		if er == nil {
			b = append(b, buf.Bytes()...)
		}
	}
	return i.tx.ResponseBodyWriter().Write(b)
}

func (i *rwInterceptor) Header() http.Header {
	return i.w.Header()
}

// Proto implements ResponseWriter.Proto.
func (i *rwInterceptor) Proto() string {
	return i.proto
}

// ResponseWriter adds Proto to http.ResponseWriter.
type ResponseWriter interface {
	http.ResponseWriter

	// Proto returns the protocol of the current request.
	Proto() string
}

// wrap wraps the interceptor into a response writer that also preserves
// the http interfaces implemented by the original response writer to avoid
// the observer effect.
// Heavily inspired in https://github.com/openzipkin/zipkin-go/blob/master/middleware/http/server.go#L218
func wrap(w http.ResponseWriter, r *http.Request, tx types.Transaction) http.ResponseWriter { // nolint:gocyclo
	i := &rwInterceptor{w: w, tx: tx, proto: r.Proto}

	var (
		hijacker, isHijacker = i.w.(http.Hijacker)
		pusher, isPusher     = i.w.(http.Pusher)
		flusher, isFlusher   = i.w.(http.Flusher)
		reader, isReader     = i.w.(io.ReaderFrom)
	)

	switch {
	case !isHijacker && !isPusher && !isFlusher && !isReader:
		return struct {
			ResponseWriter
		}{i}
	case !isHijacker && !isPusher && !isFlusher && isReader:
		return struct {
			ResponseWriter
			io.ReaderFrom
		}{i, reader}
	case !isHijacker && !isPusher && isFlusher && !isReader:
		return struct {
			ResponseWriter
			http.Flusher
		}{i, flusher}
	case !isHijacker && !isPusher && isFlusher && isReader:
		return struct {
			ResponseWriter
			http.Flusher
			io.ReaderFrom
		}{i, flusher, reader}
	case !isHijacker && isPusher && !isFlusher && !isReader:
		return struct {
			ResponseWriter
			http.Pusher
		}{i, pusher}
	case !isHijacker && isPusher && !isFlusher && isReader:
		return struct {
			ResponseWriter
			http.Pusher
			io.ReaderFrom
		}{i, pusher, reader}
	case !isHijacker && isPusher && isFlusher && !isReader:
		return struct {
			ResponseWriter
			http.Pusher
			http.Flusher
		}{i, pusher, flusher}
	case !isHijacker && isPusher && isFlusher && isReader:
		return struct {
			ResponseWriter
			http.Pusher
			http.Flusher
			io.ReaderFrom
		}{i, pusher, flusher, reader}
	case isHijacker && !isPusher && !isFlusher && !isReader:
		return struct {
			ResponseWriter
			http.Hijacker
		}{i, hijacker}
	case isHijacker && !isPusher && !isFlusher && isReader:
		return struct {
			ResponseWriter
			http.Hijacker
			io.ReaderFrom
		}{i, hijacker, reader}
	case isHijacker && !isPusher && isFlusher && !isReader:
		return struct {
			ResponseWriter
			http.Hijacker
			http.Flusher
		}{i, hijacker, flusher}
	case isHijacker && !isPusher && isFlusher && isReader:
		return struct {
			ResponseWriter
			http.Hijacker
			http.Flusher
			io.ReaderFrom
		}{i, hijacker, flusher, reader}
	case isHijacker && isPusher && !isFlusher && !isReader:
		return struct {
			ResponseWriter
			http.Hijacker
			http.Pusher
		}{i, hijacker, pusher}
	case isHijacker && isPusher && !isFlusher && isReader:
		return struct {
			ResponseWriter
			http.Hijacker
			http.Pusher
			io.ReaderFrom
		}{i, hijacker, pusher, reader}
	case isHijacker && isPusher && isFlusher && !isReader:
		return struct {
			ResponseWriter
			http.Hijacker
			http.Pusher
			http.Flusher
		}{i, hijacker, pusher, flusher}
	case isHijacker && isPusher && isFlusher && isReader:
		return struct {
			ResponseWriter
			http.Hijacker
			http.Pusher
			http.Flusher
			io.ReaderFrom
		}{i, hijacker, pusher, flusher, reader}
	default:
		return struct {
			ResponseWriter
		}{i}
	}
}
