// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"errors"
	"fmt"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/seclang"
	"github.com/corazawaf/coraza/v3/types"
)

// WAF instance is used to store configurations and rules
// Every web application should have a different WAF instance,
// but you can share an instance if you are ok with sharing
// configurations, rules and logging.
// Transactions and SecLang parser requires a WAF instance
// You can use as many WAF instances as you want, and they are
// concurrent safe
type WAF interface {
	// NewTransaction Creates a new initialized transaction for this WAF instance
	NewTransaction() types.Transaction
	NewTransactionWithID(id string) types.Transaction
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

	if c.contentInjection {
		waf.ContentInjection = true
	}

	if r := c.requestBody; r != nil {
		if r.limit <= 0 {
			return nil, errors.New("request body limit should be bigger than 0")
		}

		if r.limit < r.inMemoryLimit {
			return nil, errors.New("request body limit should be at least the memory limit")
		}
		waf.RequestBodyAccess = true
		waf.RequestBodyLimit = int64(r.limit)
		waf.RequestBodyInMemoryLimit = int64(r.inMemoryLimit)
	}

	if r := c.responseBody; r != nil {
		if r.limit <= 0 {
			return nil, errors.New("response body limit should be bigger than 0")
		}
		waf.ResponseBodyAccess = true
		waf.ResponseBodyLimit = int64(r.limit)
	}

	if c.errorCallback != nil {
		waf.ErrorLogCb = c.errorCallback
	}

	return wafWrapper{waf: waf}, nil
}

type wafWrapper struct {
	waf *corazawaf.WAF
}

// NewTransaction implements the same method on WAF.
func (w wafWrapper) NewTransaction() types.Transaction {
	return w.waf.NewTransaction()
}

// NewTransactionWithID implements the same method on WAF.
func (w wafWrapper) NewTransactionWithID(id string) types.Transaction {
	return w.waf.NewTransactionWithID(id)
}
