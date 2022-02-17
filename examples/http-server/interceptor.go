package main

import (
	"net/http"

	"github.com/corazawaf/coraza/v2"
)

type interceptor struct {
	origWriter  http.ResponseWriter
	tx          *coraza.Transaction
	headersSent bool
}

func (i *interceptor) WriteHeader(rc int) {
	if i.headersSent {
		return
	}
	for k, vv := range i.origWriter.Header() {
		for _, v := range vv {
			i.tx.AddResponseHeader(k, v)
		}
	}
	i.headersSent = true
	if it := i.tx.ProcessResponseHeaders(rc, "http/1.1"); it != nil {
		processInterruption(i.origWriter, it)
		return
	}
	i.origWriter.WriteHeader(rc)
}

func (i *interceptor) Write(b []byte) (int, error) {
	return i.tx.ResponseBodyBuffer.Write(b)
}

func (i *interceptor) Header() http.Header {
	return i.origWriter.Header()
}
