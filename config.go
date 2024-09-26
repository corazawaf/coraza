// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"io/fs"

	"github.com/redwanghb/coraza/v3/debuglog"
	"github.com/redwanghb/coraza/v3/experimental/plugins/plugintypes"
	"github.com/redwanghb/coraza/v3/internal/corazawaf"
	"github.com/redwanghb/coraza/v3/types"
)

// WAFConfig controls the behavior of the WAF.
//
// Note: WAFConfig is immutable. Each WithXXX function returns a new instance including the corresponding change.
type WAFConfig interface {
	// WithDirectives parses the directives from the given string and adds them to the WAF.
	WithDirectives(directives string) WAFConfig

	// WithDirectivesFromFile parses the directives from the given file and adds them to the WAF.
	WithDirectivesFromFile(path string) WAFConfig

	// WithRequestBodyAccess enables access to the request body.
	WithRequestBodyAccess() WAFConfig

	// WithRequestBodyLimit sets the maximum number of bytes that can be read from the request body. Bytes beyond that set
	// in WithInMemoryLimit will be buffered to disk.
	// For usability purposes body limits are enforced as int (and not int64)
	// int is a signed integer type that is at least 32 bits in size (platform-dependent size).
	// While, the theoretical settable upper limit for 32-bit machines is 2GiB,
	// it is recommended to keep this value as low as possible.
	WithRequestBodyLimit(limit int) WAFConfig

	// WithRequestBodyInMemoryLimit sets the maximum number of bytes that can be read from the request body and buffered in memory.
	// For usability purposes body limits are enforced as int (and not int64)
	// int is a signed integer type that is at least 32 bits in size (platform-dependent size).
	// While, the theoretical settable upper limit for 32-bit machines is 2GiB,
	// it is recommended to keep this value as low as possible.
	WithRequestBodyInMemoryLimit(limit int) WAFConfig

	// WithResponseBodyAccess enables access to the response body.
	WithResponseBodyAccess() WAFConfig

	// WithResponseBodyLimit sets the maximum number of bytes that can be read from the response body and buffered in memory.
	// For usability purposes body limits are enforced as int (and not int64)
	// int is a signed integer type that is at least 32 bits in size (platform-dependent size).
	// While, the theoretical settable upper limit for 32-bit machines is 2GiB,
	// it is recommended to keep this value as low as possible.
	WithResponseBodyLimit(limit int) WAFConfig

	// WithResponseBodyMimeTypes sets the mime types of responses that will be processed.
	WithResponseBodyMimeTypes(mimeTypes []string) WAFConfig

	// WithDebugLogger configures a debug logger.
	WithDebugLogger(logger debuglog.Logger) WAFConfig

	// WithErrorCallback configures an error callback that can be used
	// to log errors triggered by the WAF.
	// It contains the severity so the cb can decide to skip it or not
	WithErrorCallback(logger func(rule types.MatchedRule)) WAFConfig

	// WithRootFS configures the root file system.
	WithRootFS(fs fs.FS) WAFConfig
}

// NewWAFConfig creates a new WAFConfig with the default settings.
func NewWAFConfig() WAFConfig {
	return &wafConfig{}
}

// AuditLogConfig controls audit logging.
type AuditLogConfig interface {
	// LogRelevantOnly enables audit logging only for relevant events.
	LogRelevantOnly() AuditLogConfig

	// WithParts configures the parts of the request/response to be logged.
	WithParts(parts types.AuditLogParts) AuditLogConfig
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
// We still basically assume 64-bit usage where int are big sizes.
type wafConfig struct {
	rules                    []wafRule
	auditLog                 *auditLogConfig
	requestBodyAccess        bool
	requestBodyLimit         *int
	requestBodyInMemoryLimit *int
	responseBodyAccess       bool
	responseBodyLimit        *int
	responseBodyMimeTypes    []string
	debugLogger              debuglog.Logger
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

func (c *wafConfig) WithDebugLogger(logger debuglog.Logger) WAFConfig {
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

func (c *wafConfig) WithRequestBodyLimit(limit int) WAFConfig {
	ret := c.clone()
	ret.requestBodyLimit = &limit
	return ret
}

func (c *wafConfig) WithRequestBodyInMemoryLimit(limit int) WAFConfig {
	ret := c.clone()
	ret.requestBodyInMemoryLimit = &limit
	return ret
}

func (c *wafConfig) WithResponseBodyLimit(limit int) WAFConfig {
	ret := c.clone()
	ret.responseBodyLimit = &limit
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
	writer       plugintypes.AuditLogWriter
}

func (c *auditLogConfig) LogRelevantOnly() AuditLogConfig {
	ret := c.clone()
	ret.relevantOnly = true
	return ret
}

func (c *auditLogConfig) WithParts(parts types.AuditLogParts) AuditLogConfig {
	ret := c.clone()
	ret.parts = parts
	return ret
}

func (c *auditLogConfig) clone() *auditLogConfig {
	ret := *c // copy
	return &ret
}
