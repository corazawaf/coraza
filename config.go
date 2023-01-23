// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"io/fs"
	"math"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/loggers"
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

	// WithRequestBodyAccess enables access to the request body.
	WithRequestBodyAccess() WAFConfig

	// WithRequestBodyLimit sets the maximum number of bytes that can be read from the request body. Bytes beyond that set
	// in WithInMemoryLimit will be buffered to disk.
	// For usability purposes body limits are enforced as int (and not int64)
	// int is a signed integer type that is at least 32 bits in size (platform-dependent size).
	// The settable upper limit for 32-bit machines is 2147483647 bytes (2GiB)
	WithRequestBodyBytesLimit(limit int) WAFConfig

	// WithRequestBodyInMemoryLimit sets the maximum number of bytes that can be read from the request body and buffered in memory.
	// For usability purposes body limits are enforced as int (and not int64)
	// int is a signed integer type that is at least 32 bits in size (platform-dependent size).
	// The settable upper limit for 32-bit machines is 2147483647 bytes (2GiB)
	WithRequestBodyInMemoryBytesLimit(limit int) WAFConfig

	// WithResponseBodyAccess enables access to the response body.
	WithResponseBodyAccess() WAFConfig

	// WithResponseBodyLimit sets the maximum number of bytes that can be read from the response body and buffered in memory.
	// For usability purposes body limits are enforced as int (and not int64)
	// int is a signed integer type that is at least 32 bits in size (platform-dependent size).
	// The settable upper limit for 32-bit machines is 2147483647 bytes (2GiB)
	WithResponseBodyBytesLimit(limit int) WAFConfig

	// WithResponseBodyMimeTypes sets the mime types of responses that will be processed.
	WithResponseBodyMimeTypes(mimeTypes []string) WAFConfig

	// WithDebugLogger configures a debug logger.
	WithDebugLogger(logger loggers.DebugLogger) WAFConfig

	// WithErrorCallback configures an error callback that can be used
	// to log errors triggered by the WAF.
	// It contains the severity so the cb can decide to skip it or not
	WithErrorCallback(logger func(rule types.MatchedRule)) WAFConfig

	// WithRootFS configures the root file system.
	WithRootFS(fs fs.FS) WAFConfig
}

const UnsetLimit = math.MinInt

// NewWAFConfig creates a new WAFConfig with the default settings.
func NewWAFConfig() WAFConfig {
	return &wafConfig{
		requestBodyLimit:         UnsetLimit,
		requestBodyInMemoryLimit: UnsetLimit,
		responseBodyLimit:        UnsetLimit,
	}
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

// For usability purposes body limits are enforced as int (and not int64)
// int is a signed integer type that is at least 32 bits in size (platform-dependent size).
// 32-bit machines limit will be equal to 2GiB (2147483647 bytes)
type wafConfig struct {
	rules                    []wafRule
	auditLog                 *auditLogConfig
	contentInjection         bool
	requestBodyAccess        bool
	requestBodyLimit         int
	requestBodyInMemoryLimit int
	responseBodyAccess       bool
	responseBodyLimit        int
	responseBodyMimeTypes    []string
	debugLogger              loggers.DebugLogger
	errorCallback            func(rule types.MatchedRule)
	fsRoot                   fs.FS
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

func (c *wafConfig) WithRequestBodyAccess() WAFConfig {
	ret := c.clone()
	ret.requestBodyAccess = true
	return ret
}

func (c *wafConfig) WithResponseBodyAccess() WAFConfig {
	ret := c.clone()
	ret.responseBodyAccess = true
	return ret
}

func (c *wafConfig) WithDebugLogger(logger loggers.DebugLogger) WAFConfig {
	ret := c.clone()
	ret.debugLogger = logger
	return ret
}

func (c *wafConfig) WithErrorCallback(logger func(rule types.MatchedRule)) WAFConfig {
	ret := c.clone()
	ret.errorCallback = logger
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

func (c *wafConfig) WithRequestBodyBytesLimit(limit int) WAFConfig {
	ret := c.clone()
	ret.requestBodyLimit = limit
	return ret
}

func (c *wafConfig) WithRequestBodyInMemoryBytesLimit(limit int) WAFConfig {
	ret := c.clone()
	ret.requestBodyInMemoryLimit = limit
	return ret
}

func (c *wafConfig) WithResponseBodyBytesLimit(limit int) WAFConfig {
	ret := c.clone()
	ret.responseBodyLimit = limit
	return ret
}

func (c *wafConfig) WithResponseBodyMimeTypes(mimeTypes []string) WAFConfig {
	ret := c.clone()
	ret.responseBodyMimeTypes = mimeTypes
	return ret
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
