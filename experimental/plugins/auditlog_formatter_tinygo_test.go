// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

// Aimed to tinygo, initializing a dedicated serial writer
package plugins_test

import (
	"fmt"
	"io"

	"github.com/redwanghb/coraza/v3"
	"github.com/redwanghb/coraza/v3/experimental/plugins"
	"github.com/redwanghb/coraza/v3/experimental/plugins/plugintypes"
)

type testFormatter struct{}

func (testFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	return []byte(al.Transaction().ID()), nil
}

func (testFormatter) MIME() string {
	return "sample"
}

// ExampleRegisterAuditLogFormatter shows how to register a custom audit log formatter
// and tests the output of the formatter.
func ExampleRegisterAuditLogFormatter() {

	plugins.RegisterAuditLogWriter("serial", func() plugintypes.AuditLogWriter {
		return &serial{}
	})

	plugins.RegisterAuditLogFormatter("txid", &testFormatter{})

	w, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(`
				SecAuditEngine On
				SecAuditLogParts ABCFHZ
				SecAuditLog /dev/stdout
				SecAuditLogType Serial
				SecAuditLogFormat txid
			`),
	)
	if err != nil {
		panic(err)
	}

	tx := w.NewTransactionWithID("abc123")
	tx.ProcessLogging()
	tx.Close()

	// Output: abc123
}

// serial emulates a custom audit log writer that writes to the log in wasm overriding the default serial writer.
type serial struct {
	io.Closer
	formatter plugintypes.AuditLogFormatter
}

func (s *serial) Init(cfg plugintypes.AuditLogConfig) error {
	s.formatter = cfg.Formatter
	return nil
}

func (s *serial) Write(al plugintypes.AuditLog) error {
	bts, err := s.formatter.Format(al)
	if err != nil {
		return err
	}
	fmt.Print(string(bts))
	return nil
}

func (s *serial) Close() error { return nil }
