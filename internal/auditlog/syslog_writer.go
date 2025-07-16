// Copyright 2023 the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !windows && !plan9
// +build !tinygo,!windows,!plan9

package auditlog

import (
	"fmt"
	"log/syslog"
	"net/url"
	"path"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

var syslogDialer = syslog.Dial

type Syslog interface {
	Err(string) error
	Info(string) error
	Close() error
}

// syslogWriter is used to write logs into syslog.
type syslogWriter struct {
	Syslog
	formatter plugintypes.AuditLogFormatter
	dialer    func(network, raddr string, p syslog.Priority, tag string) (Syslog, error)
}

func NewSyslogWriter() *syslogWriter {
	s := new(syslogWriter)
	s.dialer = func(network, raddr string, p syslog.Priority, tag string) (Syslog, error) {
		return syslogDialer(network, raddr, p, tag)
	}

	return s
}

func (s *syslogWriter) Init(c plugintypes.AuditLogConfig) error {
	var network, raddr string
	if c.Target != "" {
		network, raddr = "tcp", c.Target
		if u, err := url.Parse(c.Target); err == nil {
			network, raddr = u.Scheme, path.Join(u.Host, u.Path)
		}
	}
	w, err := s.dialer(network, raddr, syslog.LOG_LOCAL0, "com.coraza.waf")
	if err != nil {
		return fmt.Errorf("syslog dial failure: %w", err)
	}
	s.Syslog = w

	s.formatter = c.Formatter

	return nil
}

func (s *syslogWriter) Write(al plugintypes.AuditLog) error {
	payload, err := s.formatter.Format(al)
	if err != nil {
		return fmt.Errorf("auditlog format failure: %w", err)
	}

	if al.Transaction().IsInterrupted() {
		if err := s.Syslog.Err(string(payload)); err != nil {
			return fmt.Errorf("error write failure: %w", err)
		}

		return nil
	}

	if err := s.Syslog.Info(string(payload)); err != nil {
		return fmt.Errorf("info write failure: %w", err)
	}

	return nil
}

var _ plugintypes.AuditLogWriter = (*syslogWriter)(nil)
