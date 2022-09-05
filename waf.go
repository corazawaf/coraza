// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"fmt"
	"io"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/seclang"
	"github.com/corazawaf/coraza/v3/types"
)

type WAF interface {
	NewTransaction(ctx context.Context) Transaction
}

func NewWAFWithConfig(config WAFConfig) (WAF, error) {
	c := config.(*wafConfig)

	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)

	if c.fsRoot != nil {
		parser.SetRoot(c.fsRoot)
	}

	for _, r := range c.rules {
		switch {
		case r.rule != nil:
			if err := waf.Rules.Add(r.rule); err != nil {
				return nil, fmt.Errorf("invalid WAF config: %w", err)
			}
		case r.str != "":
			if err := parser.FromString(r.str); err != nil {
				return nil, fmt.Errorf("invalid WAF config: %w", err)
			}
		case r.file != "":
			if err := parser.FromFile(r.file); err != nil {
				return nil, fmt.Errorf("invalid WAF config: %w", err)
			}
		}
	}

	if a := c.auditLog; a != nil {
		// TODO(anuraaga): Can't override AuditEngineOn from rules to off this way.
		if a.relevantOnly {
			waf.AuditEngine = types.AuditEngineRelevantOnly
		} else {
			waf.AuditEngine = types.AuditEngineOn
		}

		waf.AuditLogParts = a.parts

		if a.logger != nil {
			waf.AuditLogWriter = a.logger
		}
	}

	waf.ContentInjection = c.contentInjection

	if r := c.requestBody; r != nil {
		waf.RequestBodyAccess = true
		waf.RequestBodyLimit = int64(r.limit)
		waf.RequestBodyInMemoryLimit = int64(r.inMemoryLimit)
	}

	if r := c.responseBody; r != nil {
		waf.ResponseBodyAccess = true
		waf.ResponseBodyLimit = int64(r.limit)
	}

	if c.debugLogger != nil {
		waf.Logger = c.debugLogger
	}

	if c.errorLogger != nil {
		waf.ErrorLogCb = c.errorLogger
	}

	return wafWrapper{waf: waf}, nil
}

type wafWrapper struct {
	waf *corazawaf.WAF
}

func (w wafWrapper) NewTransaction(ctx context.Context) Transaction {
	return w.waf.NewTransaction(ctx)
}

type Transaction interface {
	ProcessConnection(client string, cPort int, server string, sPort int)
	ProcessURI(uri string, method string, httpVersion string)

	AddRequestHeader(key string, value string)
	ProcessRequestHeaders() *types.Interruption

	RequestBodyWriter() io.Writer
	RequestBodyReader() (io.Reader, error)
	ProcessRequestBody() (*types.Interruption, error)

	AddResponseHeader(key string, value string)
	ProcessResponseHeaders(code int, proto string) *types.Interruption

	ResponseBodyWriter() io.Writer
	ResponseBodyReader() (io.Reader, error)
	ProcessResponseBody() (*types.Interruption, error)

	ProcessLogging()

	Interrupted() bool
	InterruptionNext() *types.Interruption
	MatchedRulesNext() []types.MatchedRule

	io.Closer
}
