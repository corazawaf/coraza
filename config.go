// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"io/fs"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/loggers"
	"github.com/corazawaf/coraza/v3/types"
)

// WAFConfig controls the behavior of the WAF.
//
// Note: WAFConfig is immutable. Each WithXXX function returns a new instance including the corresponding change.
type WAFConfig interface {
	// WithRules adds rules to the WAF.
	WithRules(rules ...*corazawaf.Rule) WAFConfig

	// WithDirectives parses the directives from the given string and adds them to the WAF.
	WithDirectives(directives string) WAFConfig

	// WithDirectivesFromFile parses the directives from the given file and adds them to the WAF.
	WithDirectivesFromFile(path string) WAFConfig

	// WithAuditLog configures audit logging.
	WithAuditLog(config AuditLogConfig) WAFConfig

	// WithContentInjection enables content injection.
	WithContentInjection() WAFConfig

	// WithRequestBodyAccess configures access to the request body.
	WithRequestBodyAccess(config RequestBodyConfig) WAFConfig

	// WithResponseBodyAccess configures access to the response body.
	WithResponseBodyAccess(config ResponseBodyConfig) WAFConfig

	// WithDebugLogger configures a debug logger.
	WithDebugLogger(logger loggers.DebugLogger) WAFConfig

	// WithErrorLogger configures an error logger.
	WithErrorLogger(logger corazawaf.ErrorLogCallback) WAFConfig

	// WithRootFS configures the root file system.
	WithRootFS(fs fs.FS) WAFConfig
}

// NewWAFConfig creates a new WAFConfig with the default settings.
func NewWAFConfig() WAFConfig {
	return &wafConfig{}
}

// RequestBodyConfig controls access to the request body.
type RequestBodyConfig interface {
	// WithLimit sets the maximum number of bytes that can be read from the request body. Bytes beyond that set
	// in WithInMemoryLimit will be buffered to disk.
	WithLimit(limit int) RequestBodyConfig

	// WithInMemoryLimit sets the maximum number of bytes that can be read from the request body and buffered in memory.
	WithInMemoryLimit(limit int) RequestBodyConfig
}

// NewRequestBodyConfig returns a new RequestBodyConfig with the default settings.
func NewRequestBodyConfig() RequestBodyConfig {
	return &requestBodyConfig{}
}

// ResponseBodyConfig controls access to the response body.
type ResponseBodyConfig interface {
	// WithLimit sets the maximum number of bytes that can be read from the response body and buffered in memory.
	WithLimit(limit int) ResponseBodyConfig

	// WithMimeTypes sets the mime types of responses that will be processed.
	WithMimeTypes(mimeTypes []string) ResponseBodyConfig
}

// NewResponseBodyConfig returns a new ResponseBodyConfig with the default settings.
func NewResponseBodyConfig() ResponseBodyConfig {
	return &responseBodyConfig{}
}

// AuditLogConfig controls audit logging.
type AuditLogConfig interface {
	// LogRelevantOnly enables audit logging only for relevant events.
	LogRelevantOnly() AuditLogConfig

	// WithParts configures the parts of the request/response to be logged.
	WithParts(parts types.AuditLogParts) AuditLogConfig

	// WithLogger configures the loggers.LogWriter to write logs to.
	WithLogger(logger loggers.LogWriter) AuditLogConfig
}

// NewAuditLogConfig returns a new AuditLogConfig with the default settings.
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
	debugLogger      loggers.DebugLogger
	errorLogger      corazawaf.ErrorLogCallback
	fsRoot           fs.FS
}

func (c *wafConfig) WithRules(rules ...*corazawaf.Rule) WAFConfig {
	if len(rules) == 0 {
		return c
	}

	ret := c.clone()
	for _, r := range rules {
		ret.rules = append(ret.rules, wafRule{rule: r})
	}
	return ret
}

func (c *wafConfig) WithDirectivesFromFile(path string) WAFConfig {
	ret := c.clone()
	ret.rules = append(ret.rules, wafRule{file: path})
	return ret
}

func (c *wafConfig) WithDirectives(directives string) WAFConfig {
	ret := c.clone()
	ret.rules = append(ret.rules, wafRule{str: directives})
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

func (c *wafConfig) WithDebugLogger(logger loggers.DebugLogger) WAFConfig {
	ret := c.clone()
	ret.debugLogger = logger
	return ret
}

func (c *wafConfig) WithErrorLogger(logger corazawaf.ErrorLogCallback) WAFConfig {
	ret := c.clone()
	ret.errorLogger = logger
	return ret
}

func (c *wafConfig) WithRootFS(fs fs.FS) WAFConfig {
	ret := c.clone()
	ret.fsRoot = fs
	return ret
}

func (c *wafConfig) clone() *wafConfig {
	ret := *c // copy
	rules := make([]wafRule, len(c.rules))
	copy(rules, c.rules)
	ret.rules = rules
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
