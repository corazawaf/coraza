// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"io/fs"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/loggers"
	"github.com/corazawaf/coraza/v3/types"
)

type WAFConfig interface {
	WithRule(rule *corazawaf.Rule) WAFConfig
	WithRulesFromFile(path string) WAFConfig
	WithRulesFromString(rules string) WAFConfig

	WithAuditLog(config AuditLogConfig) WAFConfig

	WithContentInjection() WAFConfig

	WithRequestBodyAccess(config RequestBodyConfig) WAFConfig
	WithResponseBodyAccess(config ResponseBodyConfig) WAFConfig

	WithDebugLogger(logger corazawaf.DebugLogger) WAFConfig
	WithErrorLogger(logger corazawaf.ErrorLogCallback) WAFConfig

	WithFSRoot(fs fs.FS) WAFConfig
}

func NewWAFConfig() WAFConfig {
	return &wafConfig{}
}

type RequestBodyConfig interface {
	WithLimit(limit int) RequestBodyConfig
	WithInMemoryLimit(limit int) RequestBodyConfig
}

func NewRequestBodyConfig() RequestBodyConfig {
	return &requestBodyConfig{}
}

type ResponseBodyConfig interface {
	WithLimit(limit int) ResponseBodyConfig
	WithMimeTypes(mimeTypes []string) ResponseBodyConfig
}

func NewResponseBodyConfig() ResponseBodyConfig {
	return &responseBodyConfig{}
}

type AuditLogConfig interface {
	LogRelevantOnly() AuditLogConfig
	WithParts(parts types.AuditLogParts) AuditLogConfig
	WithLogger(logger loggers.LogWriter) AuditLogConfig
}

func NewAuditLogConfig() AuditLogConfig {
	return &auditLogConfig{}
}

type wafRule struct {
	rule *corazawaf.Rule
	str  string
	file string
}

type wafConfig struct {
	rules            []wafRule
	auditLog         *auditLogConfig
	contentInjection bool
	requestBody      *requestBodyConfig
	responseBody     *responseBodyConfig
	debugLogger      corazawaf.DebugLogger
	errorLogger      corazawaf.ErrorLogCallback
	fsRoot           fs.FS
}

func (c *wafConfig) WithRule(rule *corazawaf.Rule) WAFConfig {
	ret := c.clone()
	ret.rules = append(ret.rules, wafRule{rule: rule})
	return ret
}

func (c *wafConfig) WithRulesFromFile(path string) WAFConfig {
	ret := c.clone()
	ret.rules = append(ret.rules, wafRule{file: path})
	return ret
}

func (c *wafConfig) WithRulesFromString(rules string) WAFConfig {
	ret := c.clone()
	ret.rules = append(ret.rules, wafRule{str: rules})
	return ret
}

func (c *wafConfig) WithAuditLog(config AuditLogConfig) WAFConfig {
	ret := c.clone()
	ret.auditLog = config.(*auditLogConfig)
	return ret
}

func (c *wafConfig) WithContentInjection() WAFConfig {
	ret := c.clone()
	ret.contentInjection = true
	return ret
}

func (c *wafConfig) WithRequestBodyAccess(config RequestBodyConfig) WAFConfig {
	ret := c.clone()
	ret.requestBody = config.(*requestBodyConfig)
	return ret
}

func (c *wafConfig) WithResponseBodyAccess(config ResponseBodyConfig) WAFConfig {
	ret := c.clone()
	ret.responseBody = config.(*responseBodyConfig)
	return ret
}

func (c *wafConfig) WithDebugLogger(logger corazawaf.DebugLogger) WAFConfig {
	ret := c.clone()
	ret.debugLogger = logger
	return ret
}

func (c *wafConfig) WithErrorLogger(logger corazawaf.ErrorLogCallback) WAFConfig {
	ret := c.clone()
	ret.errorLogger = logger
	return ret
}

func (c *wafConfig) WithFSRoot(fs fs.FS) WAFConfig {
	ret := c.clone()
	ret.fsRoot = fs
	return ret
}

func (c *wafConfig) clone() *wafConfig {
	ret := *c // copy
	return &ret
}

type requestBodyConfig struct {
	limit         int
	inMemoryLimit int
}

func (c *requestBodyConfig) WithLimit(limit int) RequestBodyConfig {
	ret := c.clone()
	ret.limit = limit
	return ret
}

func (c *requestBodyConfig) WithInMemoryLimit(limit int) RequestBodyConfig {
	ret := c.clone()
	ret.inMemoryLimit = limit
	return ret
}

func (c *requestBodyConfig) clone() *requestBodyConfig {
	ret := *c // copy
	return &ret
}

type responseBodyConfig struct {
	limit         int
	inMemoryLimit int
	mimeTypes     []string
}

func (c *responseBodyConfig) WithLimit(limit int) ResponseBodyConfig {
	ret := c.clone()
	ret.limit = limit
	return ret
}

func (c *responseBodyConfig) WithInMemoryLimit(limit int) ResponseBodyConfig {
	ret := c.clone()
	ret.inMemoryLimit = limit
	return ret
}

func (c *responseBodyConfig) WithMimeTypes(mimeTypes []string) ResponseBodyConfig {
	ret := c.clone()
	ret.mimeTypes = mimeTypes
	return ret
}

func (c *responseBodyConfig) clone() *responseBodyConfig {
	ret := *c // copy
	return &ret
}

type auditLogConfig struct {
	relevantOnly bool
	parts        types.AuditLogParts
	logger       loggers.LogWriter
}

func (c *auditLogConfig) LogRelevantOnly() AuditLogConfig {
	ret := c.clone()
	c.relevantOnly = true
	return ret
}

func (c *auditLogConfig) WithParts(parts types.AuditLogParts) AuditLogConfig {
	ret := c.clone()
	ret.parts = parts
	return ret
}

func (c *auditLogConfig) WithLogger(logger loggers.LogWriter) AuditLogConfig {
	ret := c.clone()
	ret.logger = logger
	return ret
}

func (c *auditLogConfig) clone() *auditLogConfig {
	ret := *c // copy
	return &ret
}
