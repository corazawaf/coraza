// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
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
	h.Closer = NoopCloser
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
	if h.formatter == nil {
		return fmt.Errorf("formatter is not set")
	}
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
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", res.StatusCode)
	}
	return nil
}

var _ plugintypes.AuditLogWriter = (*httpsWriter)(nil)
