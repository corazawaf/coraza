// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package http

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/corazawaf/coraza/v3/types"
)

// rwInterceptor intercepts the ResponseWriter, so it can track response size
// and returned status code.
type rwInterceptor struct {
	w                  http.ResponseWriter
	tx                 types.Transaction
	proto              string
	statusCode         int
	isWriteHeaderFlush bool
	wroteHeader        bool
}

// WriteHeader records the status code to be sent right before the moment
// the body is being written.
func (i *rwInterceptor) WriteHeader(statusCode int) {
	if i.wroteHeader {
		log.Println("http: superfluous response.WriteHeader call")
		return
	}

	for k, vv := range i.w.Header() {
		for _, v := range vv {
			i.tx.AddResponseHeader(k, v)
		}
	}

	i.statusCode = statusCode
	if it := i.tx.ProcessResponseHeaders(statusCode, i.proto); it != nil {
		i.statusCode = obtainStatusCodeFromInterruptionOrDefault(it, i.statusCode)
		i.flushWriteHeader()
		return
	}

	i.wroteHeader = true
}

// overrideWriteHeader overrides the recorded status code
func (i *rwInterceptor) overrideWriteHeader(statusCode int) {
	i.statusCode = statusCode
}

// flushWriteHeader sends the status code to the delegate writers
func (i *rwInterceptor) flushWriteHeader() {
	if !i.isWriteHeaderFlush {
		i.w.WriteHeader(i.statusCode)
		i.isWriteHeaderFlush = true
	}
}

// Write buffers the response body until the request body limit is reach or an
// interruption is triggered, this buffer is later used to analyse the body in
// the response processor.
// If the body isn't accessible or the mime type isn't processable, the response
// body is being writen to the delegate response writer directly.
func (i *rwInterceptor) Write(b []byte) (int, error) {
	if i.tx.IsInterrupted() {
		// if there is an interruption it must be from at least phase 4 and hence
		// WriteHeader or Write should have been called and hence the status code
		// has been flushed to the delegated response writer.
		return 0, nil
	}

	if !i.wroteHeader {
		// if no header has been wrote at this point we aim to return 200
		i.WriteHeader(http.StatusOK)
	}

	if i.tx.IsResponseBodyAccessible() && i.tx.IsResponseBodyProcessable() {
		// we only buffer the response body if we are going to access
		// to it, otherwise we just send it to the response writer.
		it, n, err := i.tx.WriteResponseBody(b)
		if it != nil {
			i.overrideWriteHeader(it.Status)
			// We only flush the status code after an interruption.
			i.flushWriteHeader()
			return 0, nil
		}
		return n, err
	}

	// flush the status code before writing
	i.flushWriteHeader()

	// if response body isn't accesible or processable we write the response bytes
	// directly to the caller.
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

	i := &rwInterceptor{w: w, tx: tx, proto: r.Proto, statusCode: 200}

	responseProcessor := func(tx types.Transaction, r *http.Request) error {
		// We look for interruptions triggered at phase 4 (response headers)
		// and during writing the response body. If so, response status code
		// has been sent over the flush already.
		if tx.IsInterrupted() {
			return nil
		}

		if tx.IsResponseBodyAccessible() && tx.IsResponseBodyProcessable() {
			if it, err := tx.ProcessResponseBody(); err != nil {
				i.overrideWriteHeader(http.StatusInternalServerError)
				i.flushWriteHeader()
				return err
			} else if it != nil {
				i.overrideWriteHeader(obtainStatusCodeFromInterruptionOrDefault(it, i.statusCode))
				i.flushWriteHeader()
				return nil
			}

			// we release the buffer
			reader, err := tx.ResponseBodyReader()
			if err != nil {
				i.overrideWriteHeader(http.StatusInternalServerError)
				i.flushWriteHeader()
				return fmt.Errorf("failed to release the response body reader: %v", err)
			}

			// this is the last opportunity we have to report the resolved status code
			// as next step is write into the response writer (triggering a 200 in the
			// response status code.)
			i.flushWriteHeader()
			if _, err := io.Copy(w, reader); err != nil {
				return fmt.Errorf("failed to copy the response body: %v", err)
			}
		} else {
			i.flushWriteHeader()
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
