// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"fmt"

	"github.com/corazawaf/coraza/v4/internal/corazawaf"
	"github.com/corazawaf/coraza/v4/internal/seclang"
	"github.com/corazawaf/coraza/v4/types"
)

type Option func(*corazawaf.Options)

func WithID(id string) Option {
	return func(o *corazawaf.Options) {
		o.ID = id
	}
}

func WithContext(ctx context.Context) Option {
	return func(o *corazawaf.Options) {
		o.Context = ctx
	}
}

// WAF instance is used to store configurations and rules
// Every web application should have a different WAF instance,
// but you can share an instance if you are ok with sharing
// configurations, rules and logging.
// Transactions and SecLang parser requires a WAF instance
// You can use as many WAF instances as you want, and they are
// concurrent safe
type WAF interface {
	// NewTransaction Creates a new initialized transaction for this WAF instance
	NewTransaction(opts ...Option) types.Transaction
}

// NewWAF creates a new WAF instance with the provided configuration.
func NewWAF(config WAFConfig) (WAF, error) {
	c := config.(*wafConfig)

	waf := corazawaf.NewWAF()

	if c.debugLogger != nil {
		waf.Logger = c.debugLogger
	}

	parser := seclang.NewParser(waf)

	if c.fsRoot != nil {
		parser.SetRoot(c.fsRoot)
	}

	for _, r := range c.rules {
		switch {
		case r.rule != nil:
			if err := waf.Rules.Add(r.rule); err != nil {
				return nil, fmt.Errorf("invalid WAF config from rule: %w", err)
			}
		case r.str != "":
			if err := parser.FromString(r.str); err != nil {
				return nil, fmt.Errorf("invalid WAF config from string: %w", err)
			}
		case r.file != "":
			if err := parser.FromFile(r.file); err != nil {
				return nil, fmt.Errorf("invalid WAF config from file: %w", err)
			}
		}
	}

	populateAuditLog(waf, c)

	if err := waf.InitAuditLogWriter(); err != nil {
		return nil, fmt.Errorf("invalid WAF config from audit log: %w", err)
	}

	if c.requestBodyAccess {
		waf.RequestBodyAccess = true
	}

	if c.requestBodyLimit != nil {
		waf.RequestBodyLimit = int64(*c.requestBodyLimit)
	}

	if c.requestBodyInMemoryLimit != nil {
		waf.SetRequestBodyInMemoryLimit(int64(*c.requestBodyInMemoryLimit))
	}

	if c.responseBodyAccess {
		waf.ResponseBodyAccess = true
	}

	if c.responseBodyLimit != nil {
		waf.ResponseBodyLimit = int64(*c.responseBodyLimit)
	}

	if c.responseBodyMimeTypes != nil {
		waf.ResponseBodyMimeTypes = c.responseBodyMimeTypes
	}

	if c.errorCallback != nil {
		waf.ErrorLogCb = c.errorCallback
	}

	if err := waf.Validate(); err != nil {
		return nil, err
	}

	return wafWrapper{waf: waf}, nil
}

func populateAuditLog(waf *corazawaf.WAF, c *wafConfig) {
	if c.auditLog == nil {
		return
	}

	if c.auditLog.relevantOnly {
		waf.AuditEngine = types.AuditEngineRelevantOnly
	} else {
		waf.AuditEngine = types.AuditEngineOn
	}

	if len(c.auditLog.parts) > 0 {
		waf.AuditLogParts = c.auditLog.parts
	}

	if c.auditLog.writer != nil {
		waf.SetAuditLogWriter(c.auditLog.writer)
	}
}

type wafWrapper struct {
	waf *corazawaf.WAF
}

// NewTransaction implements the same method on WAF.
func (w wafWrapper) NewTransaction(opts ...Option) types.Transaction {
	o := &corazawaf.Options{}
	for _, opt := range opts {
		opt(o)
	}
	o.Backfill()

	return w.waf.NewTransaction(o)
}
