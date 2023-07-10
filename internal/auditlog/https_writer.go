// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// httpsWriter is used to store logs in a single file
type httpsWriter struct {
	io.Closer
	formatter plugintypes.AuditLogFormatter
	url       string
	client    *http.Client
}

func (h *httpsWriter) Init(c plugintypes.AuditLogConfig) error {
	h.formatter = c.Formatter
	h.url = c.Target
	// now we validate h.url is a valid url
	// Although the writer type is HTTPS, we allow HTTP as well
	_, err := url.Parse(h.url)
	if err != nil {
		return err
	}
	h.client = &http.Client{
		Timeout: time.Duration(1 * time.Second),
	}
	return nil
}

func (h *httpsWriter) Write(al plugintypes.AuditLog) error {
	body, err := h.formatter(al)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Coraza+v3")
	// TODO: declare content type in the formatter
	res, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 || res.StatusCode < 200 {
		return fmt.Errorf("unexpected status code %d", res.StatusCode)
	}
	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		// the stream failed, but the log was received, we don't return error
		// we cannot generate a log using the current api
		return nil
	}
	return nil
}

var _ plugintypes.AuditLogWriter = (*httpsWriter)(nil)
