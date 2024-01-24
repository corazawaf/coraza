// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package plugins_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/corazawaf/coraza/v4"
	"github.com/corazawaf/coraza/v4/experimental/plugins"
	"github.com/corazawaf/coraza/v4/experimental/plugins/plugintypes"
)

type urlWriter struct {
	url string
}

func (s *urlWriter) Init(cfg plugintypes.AuditLogConfig) error {
	s.url = cfg.Target
	return nil
}

func (s *urlWriter) Write(al plugintypes.AuditLog) error {
	res, err := http.DefaultClient.Post(s.url, "application/json", strings.NewReader(al.Transaction().ID()))
	if err != nil {
		return err
	}
	res.Body.Close()
	_, err = io.Copy(io.Discard, res.Body)
	return err
}

func (s *urlWriter) Close() error { return nil }

// ExampleRegisterAuditLogWriter shows how to register a custom audit log writer
// and tests the output of the writer.
func ExampleRegisterAuditLogWriter() {
	plugins.RegisterAuditLogWriter("url", func() plugintypes.AuditLogWriter {
		return &urlWriter{}
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Println(string(b))
	}))
	defer srv.Close()

	w, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecAuditEngine On
				SecAuditLogParts ABCFHZ
				SecAuditLog ` + srv.URL + `
				SecAuditLogType url
			`),
	)
	if err != nil {
		panic(err)
	}

	tx := w.NewTransactionWithID("xyz456")
	tx.ProcessLogging()
	tx.Close()

	// Output: xyz456
}
